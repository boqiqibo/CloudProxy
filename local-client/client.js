const net = require('net');
const http = require('http');
const https = require('https');
const url = require('url');
const crypto = require('crypto');
const tls = require('tls');
const cloudbase = require('@cloudbase/node-sdk');
const forge = require('node-forge');

// ============ 配置 ============
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

// ============ CloudBase SDK 初始化 ============
let app = null;
let useHttpGateway = false;

if (CONFIG.CLOUD_FUNCTION_URL) {
    useHttpGateway = true;
    console.log(`[INFO] Using HTTP gateway: ${CONFIG.CLOUD_FUNCTION_URL}`);
} else if (CONFIG.SECRET_ID && CONFIG.SECRET_KEY) {
    app = cloudbase.init({
        env: CONFIG.ENV_ID,
        secretId: CONFIG.SECRET_ID,
        secretKey: CONFIG.SECRET_KEY,
    });
    console.log(`[INFO] Using CloudBase SDK, env: ${CONFIG.ENV_ID}`);
} else {
    console.error('[ERROR] No valid connection method configured!');
    console.error('[ERROR] Please set either:');
    console.error('[ERROR]   1. CLOUD_FUNCTION_URL env var (for HTTP gateway mode)');
    console.error('[ERROR]   2. SECRET_ID + SECRET_KEY env vars (for SDK mode)');
    process.exit(1);
}

// ============ Logger ============
class Logger {
    static formatTime() { return new Date().toISOString(); }
    static info(message, ...args) { console.log(`[${this.formatTime()}] [INFO] ${message}`, ...args); }
    static error(message, ...args) { console.error(`[${this.formatTime()}] [ERROR] ${message}`, ...args); }
    static warn(message, ...args) { console.warn(`[${this.formatTime()}] [WARN] ${message}`, ...args); }
    static debug(message, ...args) {
        if (process.env.DEBUG) console.log(`[${this.formatTime()}] [DEBUG] ${message}`, ...args);
    }
}

// ============ MITM 证书生成 ============
// 生成自签名 CA 根证书（启动时生成一次）
const caCert = generateCACertificate();

/**
 * 生成自签名 CA 根证书
 */
function generateCACertificate() {
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);

    const attrs = [
        { name: 'commonName', value: 'CloudBase Proxy CA' },
        { name: 'organizationName', value: 'CloudBase Proxy' },
    ];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([
        { name: 'basicConstraints', cA: true },
        { name: 'keyUsage', keyCertSign: true, cRLSign: true },
    ]);

    cert.sign(keys.privateKey, forge.md.sha256.create());

    Logger.info('CA certificate generated');

    // 导出 CA 证书到文件（同时生成 PEM、CER、PFX 格式）
    const fs = require('fs');
    const path = require('path');

    // PEM 格式（通用）
    const certPem = forge.pki.certificateToPem(cert);
    fs.writeFileSync(path.join(__dirname, 'ca-cert.pem'), certPem);

    // CER/DER 格式（Windows 双击可直接安装）
    const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const derBuffer = Buffer.from(certDer, 'binary');
    fs.writeFileSync(path.join(__dirname, 'ca-cert.cer'), derBuffer);

    // PFX/PKCS12 格式（包含私钥，可设置密码）
    const p12Asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, [cert], null, { friendlyName: 'CloudBase Proxy CA' });
    const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
    const p12Buffer = Buffer.from(p12Der, 'binary');
    fs.writeFileSync(path.join(__dirname, 'ca-cert.pfx'), p12Buffer);

    Logger.info('CA certificates exported:');
    Logger.info('  ca-cert.pem  - PEM format (Linux/macOS)');
    Logger.info('  ca-cert.cer  - DER format (Windows: double-click to install)');
    Logger.info('  ca-cert.pfx  - PFX format (Windows: with private key)');
    Logger.info('Import ca-cert.cer into "Trusted Root Certification Authorities" for HTTPS proxy');

    return {
        key: keys.privateKey,
        cert: cert,
    };
}

/**
 * 为指定域名生成证书（用 CA 签发）
 */
function generateDomainCertificate(hostname) {
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = String(Date.now()) + String(Math.floor(Math.random() * 10000));
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    cert.setSubject([{ name: 'commonName', value: hostname }]);
    cert.setIssuer(caCert.cert.subject.attributes);

    const altNames = [{ type: 2, value: hostname }];
    // 如果是 IP 地址，也加上 IP 类型的 SAN
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
        altNames.push({ type: 7, ip: hostname });
    }

    cert.setExtensions([
        { name: 'subjectAltName', altNames },
        { name: 'basicConstraints', cA: false },
        { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
        { name: 'extKeyUsage', serverAuth: true },
    ]);

    cert.sign(caCert.key, forge.md.sha256.create());

    return {
        key: forge.pki.privateKeyToPem(keys.privateKey),
        cert: forge.pki.certificateToPem(cert),
    };
}

// ============ 证书缓存 ============
const certCache = new Map();

function getCachedCert(hostname) {
    if (certCache.has(hostname)) {
        return certCache.get(hostname);
    }
    const pem = generateDomainCertificate(hostname);
    certCache.set(hostname, pem);
    // 限制缓存大小
    if (certCache.size > 500) {
        const firstKey = certCache.keys().next().value;
        certCache.delete(firstKey);
    }
    return pem;
}

// ============ 向云函数发送代理请求 ============

function forwardViaSDK(proxyRequest) {
    return app.callFunction({
        name: CONFIG.FUNCTION_NAME,
        data: proxyRequest,
    }).then((result) => {
        const ret = result.result;
        if (ret && ret.statusCode && ret.body && typeof ret.body === 'string') {
            try { return JSON.parse(ret.body); } catch (e) { return ret; }
        }
        return ret;
    });
}

function forwardViaHTTP(proxyRequest) {
    return new Promise((resolve, reject) => {
        const parsedUrl = url.parse(CONFIG.CLOUD_FUNCTION_URL);
        const isHttps = parsedUrl.protocol === 'https:';
        const transport = isHttps ? https : http;
        const payload = JSON.stringify(proxyRequest);

        const options = {
            hostname: parsedUrl.hostname,
            port: parsedUrl.port || (isHttps ? 443 : 80),
            path: parsedUrl.path,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload),
            },
            timeout: CONFIG.TIMEOUT,
        };
        if (CONFIG.AUTH_TOKEN) {
            options.headers['Authorization'] = `Bearer ${CONFIG.AUTH_TOKEN}`;
        }

        const req = transport.request(options, (res) => {
            const chunks = [];
            res.on('data', (chunk) => chunks.push(chunk));
            res.on('end', () => {
                try {
                    const body = Buffer.concat(chunks).toString('utf-8');
                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        const result = JSON.parse(body);
                        if (result.body && typeof result.body === 'string') {
                            try { return resolve(JSON.parse(result.body)); } catch (e) {}
                        }
                        resolve(result);
                    } else {
                        reject(new Error(`Cloud function returned status ${res.statusCode}: ${body}`));
                    }
                } catch (e) {
                    reject(new Error(`Failed to parse cloud function response: ${e.message}`));
                }
            });
        });
        req.on('error', (err) => reject(err));
        req.on('timeout', () => { req.destroy(); reject(new Error('Cloud function request timeout')); });
        req.write(payload);
        req.end();
    });
}

function forwardToCloudFunction(proxyRequest) {
    if (useHttpGateway) return forwardViaHTTP(proxyRequest);
    return forwardViaSDK(proxyRequest);
}

// ============ MITM HTTPS 服务器（复用） ============
// 使用一个共享的 HTTPS 服务器来处理 MITM 请求
// 每个域名通过 SNI 动态返回对应证书

const mitmHttpApp = http.createServer((req, res) => {
    // 这个不应该被直接调用，所有请求通过 handleHTTPSRequest 处理
    res.writeHead(500);
    res.end('MITM server error');
});

// HTTPS MITM 服务器选项
const mitmHttpsOptions = {
    SNICallback: (servername, callback) => {
        const pem = getCachedCert(servername);
        callback(null, tls.createSecureContext({
            key: pem.key,
            cert: pem.cert,
        }));
    },
    // 默认证书（用于没有 SNI 的情况）
    ...(() => { const pem = generateDomainCertificate('localhost'); return { key: pem.key, cert: pem.cert }; })(),
};

const mitmHttpsServer = https.createServer(mitmHttpsOptions, (req, res) => {
    handleHTTPSRequest(req, res);
});

// 随机端口，监听在 localhost
let mitmPort = 0;
mitmHttpsServer.listen(0, '127.0.0.1', () => {
    mitmPort = mitmHttpsServer.address().port;
    Logger.info(`MITM HTTPS server listening on 127.0.0.1:${mitmPort}`);
});

/**
 * 处理通过 MITM 解密后的 HTTPS 请求
 * 解密后是明文 HTTP 请求，通过云函数以 https:// URL 转发
 */
function handleHTTPSRequest(req, res) {
    const targetUrl = `https://${req.headers.host}${req.url}`;
    Logger.info(`[MITM] ${req.method} ${targetUrl}`);

    // 收集请求体
    const bodyChunks = [];
    req.on('data', (chunk) => bodyChunks.push(chunk));
    req.on('end', () => {
        const body = Buffer.concat(bodyChunks);

        const proxyRequest = {
            type: 'http',
            method: req.method,
            url: targetUrl,
            headers: req.headers,
            body: body.toString('base64'),
        };

        forwardToCloudFunction(proxyRequest)
            .then((result) => {
                // 写响应头
                const statusCode = result.statusCode || 200;
                const headers = { ...(result.headers || {}) };
                // 移除可能导致问题的头
                delete headers['transfer-encoding'];
                delete headers['content-length'];
                headers['content-length'] = result.body ? Buffer.from(result.body, 'base64').length : 0;

                res.writeHead(statusCode, headers);

                // 写响应体
                if (result.body) {
                    const responseBody = Buffer.from(result.body, 'base64');
                    res.write(responseBody);
                }
                res.end();
            })
            .catch((err) => {
                Logger.error(`[MITM] Proxy error for ${targetUrl}: ${err.message}`);
                if (!res.headersSent) {
                    res.writeHead(502, { 'Content-Type': 'text/plain' });
                }
                res.end('Proxy Error: ' + err.message);
            });
    });
}

// ============ 代理服务器 ============
class ProxyClient {
    constructor() {
        this.server = null;
        this.connections = new Set();
        this.stats = {
            totalConnections: 0,
            activeConnections: 0,
            httpConnections: 0,
            httpsConnections: 0,
        };
    }

    start() {
        this.server = net.createServer((socket) => {
            this.handleConnection(socket);
        });

        this.server.maxConnections = CONFIG.MAX_CONNECTIONS;

        this.server.on('error', (err) => {
            Logger.error('Server error:', err.message);
            if (err.code === 'EADDRINUSE') {
                Logger.error(`Port ${CONFIG.PORT} is already in use`);
                process.exit(1);
            }
        });

        this.server.listen(CONFIG.PORT, CONFIG.HOST, () => {
            Logger.info(`Proxy client started on ${CONFIG.HOST}:${CONFIG.PORT}`);
            Logger.info(`Cloud function: ${CONFIG.FUNCTION_NAME}`);
            Logger.info(`Mode: ${useHttpGateway ? 'HTTP Gateway' : 'CloudBase SDK'}`);
            Logger.info(`HTTPS: MITM mode (auto-generate certificates)`);
        });

        process.on('SIGINT', () => this.shutdown());
        process.on('SIGTERM', () => this.shutdown());
    }

    shutdown() {
        Logger.info('Shutting down proxy client...');
        this.connections.forEach((socket) => {
            try { socket.destroy(); } catch (e) {}
        });
        if (this.server) {
            this.server.close(() => {
                Logger.info('Server closed');
                process.exit(0);
            });
        }
    }

    handleConnection(socket) {
        this.connections.add(socket);
        this.stats.totalConnections++;
        this.stats.activeConnections++;

        const clientAddr = `${socket.remoteAddress}:${socket.remotePort}`;
        Logger.info(`New connection from ${clientAddr} (Active: ${this.stats.activeConnections})`);

        socket.setTimeout(CONFIG.TIMEOUT);

        socket.once('error', (err) => {
            Logger.error(`Socket error from ${clientAddr}:`, err.message);
            this.cleanupSocket(socket);
        });

        socket.once('close', () => {
            this.cleanupSocket(socket);
        });

        socket.once('timeout', () => {
            Logger.warn(`Connection timeout from ${clientAddr}`);
            socket.destroy();
            this.cleanupSocket(socket);
        });

        socket.once('data', (data) => {
            this.detectProtocol(socket, data);
        });
    }

    detectProtocol(socket, data) {
        if (data.length === 0) {
            Logger.warn('Empty data received, closing connection');
            socket.destroy();
            return;
        }

        const firstByte = data[0];
        if (firstByte >= 0x43 && firstByte <= 0x5A) {
            Logger.debug('Detected HTTP protocol');
            this.handleHTTP(socket, data);
        } else {
            Logger.warn(`Unknown protocol: first byte 0x${firstByte.toString(16)}`);
            socket.destroy();
        }
    }

    handleHTTP(socket, initialData) {
        const clientAddr = `${socket.remoteAddress}:${socket.remotePort}`;
        const dataStr = initialData.toString();
        const lines = dataStr.split('\r\n');
        const firstLine = lines[0];

        if (!firstLine) {
            Logger.error(`[${clientAddr}] Invalid HTTP request`);
            socket.destroy();
            return;
        }

        const [method, target, protocol] = firstLine.split(' ');

        if (!method || !target) {
            Logger.error(`[${clientAddr}] Malformed HTTP request`);
            socket.destroy();
            return;
        }

        if (method === 'CONNECT') {
            this.handleHTTPSConnect(socket, target, clientAddr);
        } else {
            this.handleHTTPRequest(socket, initialData, method, target, clientAddr, protocol);
        }
    }

    /**
     * HTTPS CONNECT 代理处理 — MITM 中间人模式
     * 
     * 原理：
     * 1. 收到 CONNECT 请求后，回复 200
     * 2. 将客户端 socket 连接到本地 MITM HTTPS 服务器
     * 3. MITM HTTPS 服务器为该域名动态生成证书，与客户端建立 TLS
     * 4. 解密后的明文请求通过 handleHTTPSRequest 转发到云函数
     * 5. 云函数以 https:// URL 向真实目标发起请求
     */
    handleHTTPSConnect(socket, target, clientAddr) {
        const [host, portStr] = target.split(':');
        const port = parseInt(portStr) || 443;

        Logger.info(`[${clientAddr}] HTTPS CONNECT to ${host}:${port} (MITM mode)`);
        this.stats.httpsConnections++;

        // 确保证书已生成（提前缓存）
        getCachedCert(host);

        // 回复客户端隧道已建立
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

        // 连接到本地 MITM HTTPS 服务器
        const mitmSocket = net.connect({
            host: '127.0.0.1',
            port: mitmPort,
        }, () => {
            Logger.debug(`[${clientAddr}] Connected to MITM server for ${host}`);
        });

        mitmSocket.on('error', (err) => {
            Logger.error(`[${clientAddr}] MITM socket error: ${err.message}`);
            socket.destroy();
        });

        socket.on('error', (err) => {
            Logger.error(`[${clientAddr}] Client socket error in MITM: ${err.message}`);
            mitmSocket.destroy();
        });

        // 双向数据转发
        socket.pipe(mitmSocket);
        mitmSocket.pipe(socket);

        socket.once('close', () => {
            mitmSocket.destroy();
        });
        mitmSocket.once('close', () => {
            socket.destroy();
        });
    }

    /**
     * HTTP 请求代理处理
     */
    handleHTTPRequest(socket, initialData, method, target, clientAddr, protocol) {
        let targetHost, targetPort, targetPath;

        try {
            const parsedUrl = url.parse(target);

            if (!parsedUrl.host) {
                Logger.error(`[${clientAddr}] Invalid HTTP URL: ${target}`);
                socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
                socket.destroy();
                return;
            }

            targetHost = parsedUrl.hostname;
            targetPort = parsedUrl.port || 80;
            targetPath = parsedUrl.path;

            Logger.info(`[${clientAddr}] HTTP ${method} to ${targetHost}:${targetPort}${targetPath}`);
        } catch (e) {
            Logger.error(`[${clientAddr}] Failed to parse URL: ${target}`);
            socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
            socket.destroy();
            return;
        }

        this.stats.httpConnections++;

        let requestData = initialData;
        let contentLength = 0;
        let headersEnd = -1;
        let bodyReceived = 0;

        const dataStr = requestData.toString('binary');
        headersEnd = dataStr.indexOf('\r\n\r\n');

        if (headersEnd !== -1) {
            const headerPart = dataStr.substring(0, headersEnd);
            const clMatch = headerPart.match(/content-length:\s*(\d+)/i);
            if (clMatch) {
                contentLength = parseInt(clMatch[1]);
            }
            bodyReceived = requestData.length - (headersEnd + 4);
        }

        const sendProxyRequest = () => {
            const headers = this.parseHeaders(requestData);
            const headersEndIdx = requestData.toString('binary').indexOf('\r\n\r\n');
            const body = headersEndIdx !== -1 ? requestData.slice(headersEndIdx + 4) : Buffer.alloc(0);

            const proxyRequest = {
                type: 'http',
                method,
                url: `http://${targetHost}:${targetPort}${targetPath}`,
                headers,
                body: body.toString('base64'),
            };

            forwardToCloudFunction(proxyRequest)
                .then((result) => {
                    const responseBody = result.body ? Buffer.from(result.body, 'base64') : Buffer.alloc(0);
                    let responseStr = `HTTP/1.1 ${result.statusCode || 200} ${result.statusMessage || 'OK'}\r\n`;

                    if (result.headers) {
                        for (const [key, value] of Object.entries(result.headers)) {
                            if (key.toLowerCase() === 'transfer-encoding') continue;
                            if (key.toLowerCase() === 'content-length') continue;
                            responseStr += `${key}: ${value}\r\n`;
                        }
                    }
                    responseStr += `Content-Length: ${responseBody.length}\r\n`;
                    responseStr += 'Connection: close\r\n';
                    responseStr += '\r\n';

                    socket.write(responseStr);
                    if (responseBody.length > 0) {
                        socket.write(responseBody);
                    }
                    socket.end();
                })
                .catch((err) => {
                    Logger.error(`[${clientAddr}] Proxy request error: ${err.message}`);
                    socket.write('HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nProxy Error: ' + err.message);
                    socket.destroy();
                });
        };

        if (contentLength > 0 && bodyReceived < contentLength) {
            const onData = (data) => {
                requestData = Buffer.concat([requestData, data]);
                bodyReceived += data.length;
                if (bodyReceived >= contentLength) {
                    socket.removeListener('data', onData);
                    sendProxyRequest();
                }
            };
            socket.on('data', onData);
        } else {
            sendProxyRequest();
        }
    }

    parseHeaders(rawData) {
        const dataStr = rawData.toString('utf-8');
        const lines = dataStr.split('\r\n');
        const headers = {};

        for (let i = 1; i < lines.length; i++) {
            const line = lines[i];
            if (line === '') break;
            const colonIdx = line.indexOf(':');
            if (colonIdx === -1) continue;
            const key = line.substring(0, colonIdx).trim();
            const value = line.substring(colonIdx + 1).trim();
            if (key.toLowerCase().startsWith('proxy-')) continue;
            headers[key] = value;
        }

        return headers;
    }

    cleanupSocket(socket) {
        if (this.connections.has(socket)) {
            this.connections.delete(socket);
            this.stats.activeConnections--;
        }
    }
}

// ============ 启动 ============
const client = new ProxyClient();
client.start();
