# CloudBase HTTP 代理转发 — 完整复现提示词

将以下提示词复制到 AI 编辑器中，即可从零开始完整复现本项目代码。

---

## 提示词

通过 CloudBase 的云函数，实现 HTTP 代理转发功能。云函数作为服务端运行在云端，本地有一个 Node.js 客户端，客户端在本地开启 `0.0.0.0:10888` 端口，用户访问客户端时，客户端将 HTTP 和 HTTPS 流量转发到云函数，云函数再代理转发到真实的目标服务器并返回响应。

要求：
- 云函数和本地都使用 Node.js 实现
- 参考下方提供的 `node_proxy/proxy-server.js` 的架构风格（Logger 类、ProxyServer 类、协议检测、HTTP/HTTPS 处理等）

### 项目目录结构

```
项目根目录/
├── cloudfunctions/
│   └── http-proxy/
│       ├── index.js          # 云函数入口（Event Function 格式）
│       └── package.json
├── local-client/
│   ├── client.js             # 本地代理客户端
│   └── package.json
└── node_proxy/               # 原始参考代码（已存在）
    └── proxy-server.js
```

### 一、云函数 `cloudfunctions/http-proxy/index.js`

采用 CloudBase Event Function 格式（`exports.main = async (event, context) => {}`），不是 HTTP Function 格式。

**核心功能**：
1. **HTTP/HTTPS 代理转发**（`type: 'http'`）：接收完整的请求信息（method, url, headers, body），向真实目标发起请求并返回响应
2. **隧道代理**（`type: 'tunnel'`）：直接连接目标服务器，透传数据

**关键实现细节**：
- `makeRequest(options, body)`：执行 HTTP/HTTPS 请求，返回 `{ statusCode, statusMessage, headers, body(base64编码) }`
- `handleHttpProxy(proxyRequest)`：解析目标 URL，构造请求选项，支持 HTTP 和 HTTPS
  - **重要**：HTTPS 请求必须设置 `rejectUnauthorized: false`，允许自签名/过期/域名不匹配的证书
  - 修正 Host 头：`options.headers['Host'] = parsedUrl.host`，删除小写的 `host`
  - body 是 base64 编码，需要 `Buffer.from(body, 'base64')` 解码后发送，并重算 `Content-Length`
- `handleTunnelProxy(proxyRequest)`：用 `https.connect` 或 `http.connect` 连接目标，透传数据
- 云函数入口 `exports.main`：
  - 健康检查：`event.query.health === '1'` 时返回 ok
  - **关键判断逻辑**：区分 SDK 调用和 HTTP 网关调用
    - SDK 调用时 `event` 就是 proxyRequest 对象，`event.type` 为 `'http'`，`event.body` 是 base64 字符串
    - 网关调用时 `event.body` 是 JSON 字符串，没有 `event.type` 字段
    - 判断条件：`event.body && typeof event.body === 'string' && !event.type` 时按网关方式解析
    - **如果不加 `!event.type` 条件，POST 请求的 base64 body 会被误判为网关 JSON，导致 JSON.parse 失败返回 400 错误**
  - 返回格式：`{ statusCode: 200, body: JSON.stringify(result) }`
  - 错误时返回 `{ statusCode: 502, body: JSON.stringify({error, message}) }`
- `package.json` 无额外依赖（只用 Node.js 内置模块）

### 二、本地客户端 `local-client/client.js`

**依赖**：`@cloudbase/node-sdk`（调用云函数）、`node-forge`（生成 MITM 证书）

**架构**：参考 `node_proxy/proxy-server.js` 的 ProxyServer 类结构，但重命名为 ProxyClient

**配置**：
```javascript
const CONFIG = {
    HOST: '0.0.0.0',
    PORT: 10888,
    TIMEOUT: 30000,
    MAX_CONNECTIONS: 1000,
    ENV_ID: process.env.ENV_ID || 'cloudbase-envid',
    FUNCTION_NAME: 'http-proxy',
    SECRET_ID: process.env.SECRET_ID || '',
    SECRET_KEY: process.env.SECRET_KEY || '',
    CLOUD_FUNCTION_URL: process.env.CLOUD_FUNCTION_URL || '',
    AUTH_TOKEN: process.env.AUTH_TOKEN || '',
};
```

**CloudBase SDK 初始化**（三种模式，优先级从高到低）：
1. `CLOUD_FUNCTION_URL` 存在 → 使用 HTTP 网关模式
2. `SECRET_ID` + `SECRET_KEY` 存在 → 使用 CloudBase Node SDK 模式
3. 都没有 → 报错退出

**核心模块**：

#### 1. MITM 证书生成（HTTPS 代理关键）

- `generateCACertificate()`：启动时生成一次自签名 CA 根证书
  - RSA 2048 位，有效期 10 年
  - CN: `CloudBase Proxy CA`，Org: `CloudBase Proxy`
  - 扩展：`basicConstraints: cA=true`，`keyUsage: keyCertSign, cRLSign`
  - **启动时自动导出三种格式的证书文件到 `local-client/` 目录**：
    - `ca-cert.pem`：PEM 格式（Linux/macOS）
    - `ca-cert.cer`：DER 二进制格式（Windows 双击可直接安装）
    - `ca-cert.pfx`：PFX/PKCS12 格式（含私钥）
  - 导出代码：用 `forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes()` 生成 DER
  - 用 `forge.pkcs12.toPkcs12Asn1(keys.privateKey, [cert], null, {friendlyName})` 生成 PFX
  - 返回 `{ key: privateKey, cert: cert }`（forge 对象，不是 PEM 字符串）

- `generateDomainCertificate(hostname)`：为指定域名动态生成证书，用 CA 签发
  - RSA 2048，有效期 1 年
  - CN 设为 hostname，Issuer 设为 CA 的 subject
  - 扩展：`subjectAltName`（包含域名和 IP 类型的 SAN）、`keyUsage: digitalSignature, keyEncipherment`、`extKeyUsage: serverAuth`
  - **IP 地址检测**：如果 hostname 匹配 `/^\d+\.\d+\.\d+\.\d+$/`，添加 `{type: 7, ip: hostname}` 到 SAN
  - 返回 `{ key: PEM字符串, cert: PEM字符串 }`（用于 tls.createSecureContext）

- 证书缓存 `certCache`：Map 结构，限制 500 个条目，LRU 淘汰

#### 2. MITM HTTPS 服务器

- 使用 `https.createServer` + `SNICallback` 实现共享端口的动态证书
- `SNICallback(servername, callback)`：根据域名从缓存获取证书，`callback(null, tls.createSecureContext({key, cert}))`
- 默认证书：为 `localhost` 预生成
- 监听 `127.0.0.1` 随机端口（`listen(0, '127.0.0.1')`），端口号存入 `mitmPort`

#### 3. 请求转发

- `forwardViaSDK(proxyRequest)`：通过 `app.callFunction({name, data})` 调用
  - 解析返回值：`result.result` 是云函数返回的 `{statusCode, body}`
  - `body` 是 JSON 字符串，需要 `JSON.parse` 得到代理结果
  - 判断条件：`ret.statusCode && ret.body && typeof ret.body === 'string'` → 解析
- `forwardViaHTTP(proxyRequest)`：通过 HTTP POST 调用云函数网关
  - 支持自定义 `AUTH_TOKEN`（Bearer 头）
  - 解析响应：同上双重 JSON 解析
- `forwardToCloudFunction(proxyRequest)`：根据模式分发

#### 4. 代理服务器（ProxyClient 类）

- 用 `net.createServer` 创建 TCP 服务器，监听 `0.0.0.0:10888`
- 连接管理：`connections` Set，`stats` 统计
- 协议检测 `detectProtocol`：首字节 `0x43-0x5A` → HTTP 协议（覆盖 C-Z，即 CONNECT/DELETE/GET/HEAD 等方法开头）

**HTTP 请求处理 `handleHTTPRequest`**：
1. 解析请求行，提取 method、target URL
2. 如果是 `CONNECT` 方法 → `handleHTTPSConnect`
3. 否则解析 URL 获取 host/port/path
4. 收集请求体（按 Content-Length 判断是否需要继续接收数据）
5. 构造 `proxyRequest = { type: 'http', method, url: 'http://host:port/path', headers, body: base64 }`
6. 调用 `forwardToCloudFunction`，将返回的 base64 body 解码后构造 HTTP 响应写回 socket
7. 响应头过滤：跳过 `transfer-encoding` 和 `content-length`，重算 `Content-Length`

**HTTPS 请求处理 `handleHTTPSConnect`（MITM 模式）**：
1. 解析 CONNECT 目标：`host:port`
2. 预生成域名证书：`getCachedCert(host)`
3. 回复客户端：`HTTP/1.1 200 Connection Established\r\n\r\n`
4. 创建到本地 MITM HTTPS 服务器的 TCP 连接：`net.connect({host:'127.0.0.1', port: mitmPort})`
5. 双向 pipe：`socket.pipe(mitmSocket)` 和 `mitmSocket.pipe(socket)`
6. 错误处理和 close 清理

**MITM 请求处理 `handleHTTPSRequest`**（由 MITM HTTPS 服务器的 request 事件触发）：
1. 构造目标 URL：`https://${req.headers.host}${req.url}`
2. 收集请求体，构造 `proxyRequest = { type: 'http', method, url: 'https://...', headers, body: base64 }`
3. 调用 `forwardToCloudFunction`
4. 写响应：过滤 `transfer-encoding` 和 `content-length`，重算 `content-length`，base64 解码 body

**请求头解析 `parseHeaders`**：
- 遍历原始数据的行，`:` 分割 key/value
- 过滤 `proxy-` 开头的头
- 注意：同名 header 会覆盖（简单实现，对多数场景足够）

### 三、部署步骤

1. 安装云函数依赖：`cd cloudfunctions/http-proxy && npm install`（无额外依赖，可跳过）
2. 安装本地客户端依赖：`cd local-client && npm install`
3. 通过 CloudBase 创建云函数：
   - 使用 `createFunction` 工具
   - 参数：`name: 'http-proxy'`, `runtime: 'Nodejs18.15'`, `handler: 'index.main'`, `timeout: 60`
   - `isWaitInstall: true`
   - `functionRootPath` 指向 `cloudfunctions` 目录
4. 配置网关访问路径（可选）：使用 `callCloudApi` 调用 `CreateCloudBaseGWAPI`
5. 启动本地客户端：
   - SDK 模式：设置 `SECRET_ID` + `SECRET_KEY` 环境变量，运行 `npm start`
   - HTTP 网关模式：设置 `CLOUD_FUNCTION_URL` 环境变量，运行 `npm start`

### 四、已修复的关键问题

1. **POST 请求返回空**：云函数入口判断 `event.body` 是字符串时按网关方式解析，但 SDK 调用时 `event.body` 是 base64 字符串。修复：加 `!event.type` 条件，SDK 调用时 `event.type` 存在
2. **HTTPS 网站卡住**：云函数是无状态的，无法维持 TLS 握手多轮通信。修复：改用 MITM 中间人模式，本地解密 HTTPS 流量后以明文 HTTP 转发
3. **不安全 HTTPS 证书无法访问**：云函数 `https.request` 默认验证证书。修复：加 `rejectUnauthorized: false`
4. **Windows 证书导入不便**：只生成 PEM 格式。修复：同时生成 CER（DER）和 PFX 格式

### 五、参考代码风格

以下是 `node_proxy/proxy-server.js` 的关键结构（供参考风格，不需要照搬 SOCKS5 部分）：

```javascript
const net = require('net');
const http = require('http');
const url = require('url');

const CONFIG = { HOST: '0.0.0.0', PORT: 10800, TIMEOUT: 30000, MAX_CONNECTIONS: 1000 };

class Logger {
    static formatTime() { return new Date().toISOString(); }
    static info(message, ...args) { console.log(`[${this.formatTime()}] [INFO] ${message}`, ...args); }
    static error(message, ...args) { console.error(`[${this.formatTime()}] [ERROR] ${message}`, ...args); }
    static warn(message, ...args) { console.warn(`[${this.formatTime()}] [WARN] ${message}`, ...args); }
    static debug(message, ...args) { if (process.env.DEBUG) console.log(`[${this.formatTime()}] [DEBUG] ${message}`, ...args); }
}

class ProxyServer {
    constructor() { this.server = null; this.connections = new Set(); this.stats = {...}; }
    start() { this.server = net.createServer(socket => this.handleConnection(socket)); ... }
    handleConnection(socket) { /* 错误/超时/close 处理，once('data') 触发协议检测 */ }
    detectProtocol(socket, data) { /* 首字节判断：0x05=SOCKS5, 0x43-0x5A=HTTP */ }
    handleHTTP(socket, initialData) { /* 解析请求行，CONNECT → handleHTTPSConnect，其他 → handleHTTPRequest */ }
    handleHTTPSConnect(socket, target, clientAddr) { /* 回复 200，net.connect 连接目标，pipe 双向转发 */ }
    handleHTTPRequest(socket, initialData, method, target, clientAddr) { /* 解析 URL，net.connect 连接目标，重写请求头，pipe 转发 */ }
    parseHeaders(rawData) { /* 遍历行，冒号分割，过滤 proxy- 头 */ }
    cleanupSocket(socket) { /* 从 connections Set 中移除 */ }
}
```
