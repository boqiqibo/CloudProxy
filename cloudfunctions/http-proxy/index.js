const http = require('http');
const https = require('https');
const url = require('url');

// ============ Logger ============
class Logger {
    static formatTime() {
        return new Date().toISOString();
    }
    static info(message, ...args) {
        console.log(`[${this.formatTime()}] [INFO] ${message}`, ...args);
    }
    static error(message, ...args) {
        console.error(`[${this.formatTime()}] [ERROR] ${message}`, ...args);
    }
}

// ============ 核心代理逻辑 ============

/**
 * 执行 HTTP/HTTPS 请求
 */
function makeRequest(options, body) {
    return new Promise((resolve, reject) => {
        const transport = options.protocol === 'https:' ? https : http;

        const req = transport.request(options, (res) => {
            const chunks = [];
            res.on('data', (chunk) => chunks.push(chunk));
            res.on('end', () => {
                const responseBody = Buffer.concat(chunks);
                resolve({
                    statusCode: res.statusCode,
                    statusMessage: res.statusMessage,
                    headers: res.headers,
                    body: responseBody.toString('base64'),
                });
            });
        });

        req.on('error', (err) => reject(err));

        req.setTimeout(30000, () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });

        if (body && body.length > 0) {
            req.write(body);
        }
        req.end();
    });
}

/**
 * 处理 HTTP 代理请求
 */
async function handleHttpProxy(proxyRequest) {
    const { method, url: targetUrl, headers, body } = proxyRequest;

    Logger.info(`HTTP Proxy: ${method} ${targetUrl}`);

    let parsedUrl;
    try {
        parsedUrl = new URL(targetUrl);
    } catch (e) {
        throw new Error(`Invalid URL: ${targetUrl}`);
    }

    const isHttps = parsedUrl.protocol === 'https:';
    const requestPort = parsedUrl.port || (isHttps ? '443' : '80');

    const options = {
        protocol: parsedUrl.protocol,
        hostname: parsedUrl.hostname,
        port: requestPort,
        path: parsedUrl.pathname + parsedUrl.search,
        method: method,
        headers: { ...headers },
    };

    // 允许不安全的 HTTPS 证书（自签名、过期、域名不匹配等）
    if (isHttps) {
        options.rejectUnauthorized = false;
    }

    // 修正 Host 头
    options.headers['Host'] = parsedUrl.host;
    delete options.headers['host'];

    const bodyBuffer = body ? Buffer.from(body, 'base64') : null;
    if (bodyBuffer && bodyBuffer.length > 0) {
        options.headers['Content-Length'] = bodyBuffer.length;
    }

    return await makeRequest(options, bodyBuffer);
}

/**
 * 处理 HTTPS 隧道代理请求
 */
async function handleTunnelProxy(proxyRequest) {
    const { host, port, data } = proxyRequest;

    Logger.info(`Tunnel Proxy: ${host}:${port}`);

    const isHttps = parseInt(port) === 443;
    const transport = isHttps ? https : http;

    return new Promise((resolve, reject) => {
        const targetSocket = transport.connect({
            host: host,
            port: port,
            timeout: 30000,
        }, () => {
            if (data) {
                const dataBuffer = Buffer.from(data, 'base64');
                targetSocket.write(dataBuffer);
            }
        });

        const chunks = [];
        targetSocket.on('data', (chunk) => chunks.push(chunk));
        targetSocket.on('end', () => {
            const responseBody = Buffer.concat(chunks);
            resolve({
                statusCode: 200,
                statusMessage: 'OK',
                headers: { 'Content-Type': 'application/octet-stream' },
                body: responseBody.toString('base64'),
            });
        });

        targetSocket.on('error', (err) => {
            reject(err);
        });

        targetSocket.setTimeout(30000, () => {
            targetSocket.destroy();
            reject(new Error('Tunnel connection timeout'));
        });
    });
}

// ============ 云函数入口 (Event Function 格式) ============

exports.main = async (event, context) => {
    // 健康检查
    if (event.query && event.query.health === '1') {
        return { ok: true, message: 'http-proxy cloud function is running' };
    }

    try {
        // 支持两种调用方式：
        // 1. 直接传入 proxyRequest 对象（SDK 调用：event 就是 proxyRequest）
        // 2. 通过 HTTP 触发时，请求体在 event.body 中（网关调用）
        let proxyRequest = event;

        // 判断是否通过 HTTP 网关触发：
        // - 网关触发时 event 会有 headers、httpMethod 等字段，body 是 JSON 字符串
        // - SDK 调用时 event 就是 proxyRequest，body 是 base64 编码的数据
        if (event.body && typeof event.body === 'string' && !event.type) {
            try {
                proxyRequest = JSON.parse(event.body);
            } catch (e) {
                return {
                    statusCode: 400,
                    body: JSON.stringify({ error: 'Invalid JSON body' }),
                };
            }
        }

        if (!proxyRequest || !proxyRequest.type) {
            return {
                statusCode: 400,
                body: JSON.stringify({ error: 'Missing proxy request type' }),
            };
        }

        let result;

        if (proxyRequest.type === 'http') {
            result = await handleHttpProxy(proxyRequest);
        } else if (proxyRequest.type === 'tunnel') {
            result = await handleTunnelProxy(proxyRequest);
        } else {
            return {
                statusCode: 400,
                body: JSON.stringify({ error: `Unknown proxy type: ${proxyRequest.type}` }),
            };
        }

        return {
            statusCode: 200,
            body: JSON.stringify(result),
        };
    } catch (err) {
        Logger.error(`Proxy error: ${err.message}`);
        return {
            statusCode: 502,
            body: JSON.stringify({
                error: 'Proxy request failed',
                message: err.message,
            }),
        };
    }
};
