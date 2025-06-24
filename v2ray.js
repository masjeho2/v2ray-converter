/**
 * @file bot.js
 * @description Bot Telegram untuk mendeteksi jenis link V2Ray (VMess, VLESS, Trojan)
 * dan mengonversinya ke format Clash YAML yang spesifik sesuai dengan link input,
 * termasuk penanganan tipe network (ws, grpc, tcp).
 * Output akan fokus hanya pada tipe link dan network yang dikirimkan.
 *
 * Instal dependensi:
 * npm install telegraf dotenv
 *
 * Jalankan bot:
 * node bot.js
 */

// Load environment variables from .env file
require('dotenv').config();

// Import Telegraf class from telegraf library
const { Telegraf } = require('telegraf');

// Get bot token from BOT_TOKEN environment variable
// Make sure you have set BOT_TOKEN in your .env file
const BOT_TOKEN = process.env.BOT_TOKEN;

// Ensure BOT_TOKEN is available
if (!BOT_TOKEN) {
    console.error('Error: BOT_TOKEN not found in .env file. Please set it.');
    process.exit(1); // Exit process if token is missing
}

// Initialize Telegraf bot object with your token
const bot = new Telegraf(BOT_TOKEN);

/**
 * V2RayConfig Class: Responsible for parsing various V2Ray link types
 * (VMess, VLESS, Trojan) and converting them to relevant Clash YAML formats,
 * including handling network options (WebSocket, gRPC).
 */
class V2RayConfig {
    /**
     * Constructor for V2RayConfig.
     * @param {string} link V2Ray link (VMess, VLESS, or Trojan) to be parsed.
     */
    constructor(link) {
        this.originalLink = link;
        this.type = null; // Protocol type (vmess, vless, trojan)
        this.config = {}; // Object to store parsed configuration properties

        this.parse(link);
    }

    /**
     * Detects link type and calls the appropriate parser.
     * @param {string} link V2Ray link.
     * @throws {Error} If link format is invalid or unsupported.
     */
    parse(link) {
        if (link.startsWith('vmess://')) {
            this.type = 'vmess';
            this._parseVmess(link);
        } else if (link.startsWith('vless://')) {
            this.type = 'vless';
            this._parseVless(link);
        } else if (link.startsWith('trojan://')) {
            this.type = 'trojan';
            this._parseTrojan(link);
        } else {
            throw new Error("Unsupported V2Ray link type or invalid format. Only VMess, VLESS, or Trojan.");
        }
    }

    /**
     * Parses a VMess link.
     * @param {string} link VMess link.
     * @private
     */
    _parseVmess(link) {
        try {
            const base64Part = link.split('vmess://')[1];
            const paddedBase64 = base64Part.length % 4 === 0 ? base64Part : base64Part + '='.repeat(4 - (base64Part.length % 4));
            const decoded = Buffer.from(paddedBase64, 'base64').toString('utf8');
            const jsonConfig = JSON.parse(decoded);

            this.config = {
                address: jsonConfig.add,
                port: jsonConfig.port,
                id: jsonConfig.id,
                alterId: jsonConfig.aid,
                network: jsonConfig.net,
                type: jsonConfig.type, // "none" or other
                tls: jsonConfig.tls === 'tls', // Convert to boolean
                sni: jsonConfig.sni || jsonConfig.add,
                ps: jsonConfig.ps,
                path: jsonConfig.path || '/', // path for ws/grpc
                host: jsonConfig.host || '', // host header for ws
                serviceName: jsonConfig.path || '', // For gRPC, path is often the serviceName
            };
        } catch (error) {
            throw new Error(`Failed to parse VMess link: ${error.message}.`);
        }
    }

    /**
     * Parses a VLESS link.
     * @param {string} link VLESS link.
     * @private
     */
    _parseVless(link) {
        try {
            const [basePart, aliasPart] = link.split('#');
            const [protocolAndAuth, paramsPart] = basePart.split('?');
            const [id, addressPort] = protocolAndAuth.split('vless://')[1].split('@');
            const [address, port] = addressPort.split(':');

            this.config.id = id;
            this.config.address = address;
            this.config.port = parseInt(port, 10);
            this.config.ps = aliasPart ? decodeURIComponent(aliasPart) : `vless-proxy-${address}`;

            // Initialize defaults
            this.config.tls = false;
            this.config.network = 'tcp';
            this.config.path = '/';
            this.config.host = '';
            this.config.sni = address;
            this.config.serviceName = ''; // Specific for gRPC

            if (paramsPart) {
                paramsPart.split('&').forEach(param => {
                    let [key, value] = param.split('=');
                    key = key.toLowerCase();
                    value = decodeURIComponent(value || '');

                    switch (key) {
                        case 'security':
                            if (value === 'tls') this.config.tls = true;
                            break;
                        case 'type':
                            this.config.network = value;
                            break;
                        case 'path':
                            this.config.path = value;
                            break;
                        case 'host':
                            this.config.host = value;
                            break;
                        case 'sni':
                            this.config.sni = value;
                            break;
                        case 'servicename':
                            this.config.serviceName = value;
                            break;
                        case 'flow':
                            this.config.flow = value;
                            break;
                    }
                });
            }
            if (this.config.network === 'grpc' && !this.config.serviceName) {
                this.config.serviceName = this.config.path;
            }
        } catch (error) {
            throw new Error(`Failed to parse VLESS link: ${error.message}.`);
        }
    }

    /**
     * Parses a Trojan link.
     * @param {string} link Trojan link.
     * @private
     */
    _parseTrojan(link) {
        try {
            const [basePart, aliasPart] = link.split('#');
            const [protocolAndAuth, paramsPart] = basePart.split('?');
            const [password, addressPort] = protocolAndAuth.split('trojan://')[1].split('@');
            const [address, port] = addressPort.split(':');

            this.config.password = password;
            this.config.address = address;
            this.config.port = parseInt(port, 10);
            this.config.ps = aliasPart ? decodeURIComponent(aliasPart) : `trojan-proxy-${address}`;

            // Initialize defaults
            this.config.tls = false;
            this.config.network = 'tcp';
            this.config.path = '/';
            this.config.host = '';
            this.config.sni = address;
            this.config.serviceName = ''; // Specific for gRPC

            if (paramsPart) {
                paramsPart.split('&').forEach(param => {
                    let [key, value] = param.split('=');
                    key = key.toLowerCase();
                    value = decodeURIComponent(value || '');

                    switch (key) {
                        case 'security':
                            if (value === 'tls') this.config.tls = true;
                            break;
                        case 'type':
                            this.config.network = value;
                            break;
                        case 'path':
                            this.config.path = value;
                            break;
                        case 'host':
                            this.config.host = value;
                            break;
                        case 'sni':
                            this.config.sni = value;
                            break;
                        case 'servicename':
                            this.config.serviceName = value;
                            break;
                    }
                });
            }
            if (this.config.network === 'grpc' && !this.config.serviceName) {
                this.config.serviceName = this.config.path;
            }
        } catch (error) {
            throw new Error(`Failed to parse Trojan link: ${error.message}.`);
        }
    }

    /**
     * Converts parsed configuration to VLESS link format.
     * This method is primarily relevant if the original input was VMess.
     * @returns {string} Converted VLESS link.
     */
    toVlessLink() {
        // This method will only be called for VMess input type
        // and provides a VLESS link equivalent.
        const { id, address, port, network, tls, sni, ps, path, host, serviceName } = this.config;
        let vlessLink = `vless://${id}@${address}:${port}?type=${network}`;

        const params = [];
        if (network === 'ws') {
            params.push(`path=${encodeURIComponent(path || '/')}`);
            if (host) {
                params.push(`host=${encodeURIComponent(host)}`);
            }
        } else if (network === 'grpc') {
            params.push(`serviceName=${encodeURIComponent(serviceName || '')}`);
            if (path && path !== serviceName) {
                params.push(`path=${encodeURIComponent(path)}`);
            }
        }

        if (tls) {
            params.push('security=tls');
            if (sni) {
                params.push(`sni=${encodeURIComponent(sni)}`);
            }
        }

        if (params.length > 0) {
            vlessLink += `&${params.join('&')}`;
        }

        if (ps) {
            vlessLink += `#${encodeURIComponent(ps)}`;
        }

        return vlessLink;
    }

    /**
     * Converts parsed configuration to Clash YAML format (VMess type).
     * @returns {string} Clash YAML configuration for VMess proxy.
     */
    toClashVmessYaml() {
        // When converting from VLESS/Trojan to VMess, we need UUID and AlterID.
        // Assumption: use their ID/password as UUID. AlterID defaults to 0.
        this.config.id = this.config.id || this.config.password || 'auto-uuid';
        this.config.alterId = this.config.alterId || 0;

        const { address, port, id, alterId, network, tls, sni, ps, path, host, serviceName } = this.config;
        const servername = sni || address;
        const skipCertVerify = tls ? 'true' : 'false';

        let yaml = `
  - name: ${ps || 'vmess-proxy'}
    server: ${address}
    type: vmess
    port: ${port}
    uuid: ${id}
    alterId: ${alterId}
    cipher: auto`;

        if (tls) {
            yaml += `
    tls: true
    skip-cert-verify: ${skipCertVerify}
    servername: ${servername}`;
        } else {
            yaml += `
    tls: false`;
        }

        yaml += `
    network: ${network}`;

        if (network === 'ws') {
            yaml += `
    ws-opts:
      path: ${path || '/'}`;
            if (host) {
                yaml += `
      headers:
        Host: ${host}`;
            }
        } else if (network === 'grpc') {
            yaml += `
    grpc-opts:
      service-name: ${serviceName || ''}`;
        }
        yaml += `
    udp: true`;

        return yaml;
    }

    /**
     * Converts parsed configuration to Clash YAML format (VLESS type).
     * @returns {string} Clash YAML configuration for VLESS proxy.
     */
    toClashVlessYaml() {
        // When converting from VMess/Trojan to VLESS, we need UUID.
        // Assumption: use their ID/password as VLESS UUID.
        this.config.id = this.config.id || this.config.password || 'auto-uuid';

        const { id, address, port, network, tls, sni, ps, path, host, serviceName, flow } = this.config;
        const servername = sni || address;
        const skipCertVerify = tls ? 'true' : 'false';

        let yaml = `
  - name: ${ps || 'vless-proxy'}
    server: ${address}
    port: ${port}
    type: vless
    uuid: ${id}
    tls: ${tls}`;

        if (tls) {
            yaml += `
    servername: ${servername}
    skip-cert-verify: ${skipCertVerify}`;
        }

        yaml += `
    network: ${network}`;

        if (network === 'ws') {
            yaml += `
    ws-opts:
      path: ${path || '/'}`;
            if (host) {
                yaml += `
      headers:
        Host: ${host}`;
            }
        } else if (network === 'grpc') {
            yaml += `
    grpc-opts:
      service-name: ${serviceName || ''}`;
        }
        if (flow) {
            yaml += `
    flow: ${flow}`;
        }
        yaml += `
    udp: true`;

        return yaml;
    }

    /**
     * Converts parsed configuration to Clash YAML format (Trojan type).
     * @returns {string} Clash YAML configuration for Trojan proxy.
     */
    toClashTrojanYaml() {
        // When converting from VMess/VLESS to Trojan, we need a password.
        // Assumption: use their ID/UUID as Trojan password.
        this.config.password = this.config.password || this.config.id || 'auto-password';

        const { address, port, tls, sni, ps, network, path, host, password, serviceName } = this.config;
        const servername = sni || address;
        const skipCertVerify = tls ? 'true' : 'false';

        let yaml = `
  - name: ${ps || 'trojan-proxy'}
    server: ${address}
    port: ${port}
    type: trojan
    password: ${password}
    tls: ${tls}`;

        if (tls) {
            yaml += `
    servername: ${servername}
    skip-cert-verify: ${skipCertVerify}`;
        }
        
        yaml += `
    network: ${network}`;

        if (network === 'ws') {
            yaml += `
    ws-opts:
      path: ${path || '/'}`;
            if (host) {
                yaml += `
      headers:
        Host: ${host}`;
            }
        } else if (network === 'grpc') {
            yaml += `
    grpc-opts:
      service-name: ${serviceName || ''}`;
        }
        yaml += `
    udp: true`;

        return yaml;
    }
}

// --- Bot Command Handlers ---

// Handler for /start command
bot.start((ctx) => {
    ctx.reply(
        'Halo! Kirimkan link V2Ray (VMess, VLESS, atau Trojan) untuk saya konversi ke format Clash YAML yang relevan.\n\n' +
        'Bot ini akan mendeteksi tipe protokol dan network (WebSocket, gRPC, TCP, dll.) dan hanya menampilkan konversi yang sesuai dengan input Anda.\n\n' +
        'Contoh link:\n' +
        '• VMess WS: `vmess://eyJhZGRyZXNzIjoiaG9zdC5jb20iLCJwb3J0IjoiNDQzIiwiaWQiOiJ1dWlkIiwiYWlkIjoiMCIsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJ0bHMiOiJ0bHMiLCJzbmkiOiJob3N0LmNvbSIsInBzIjoiTXlWaW5nIFdTIn0=`\n' +
        '• VMess gRPC: `vmess://eyJhZGRyZXNzIjoiZ3JwYy5leGFtcGxlLmNvbSIsImlkIjoidXVpZCIsImFpZCI6IjY0IiwibmV0IjoiZ3JwYyIsInR5cGUiOiJub25lIiwidGxzIjoidGxzIiwic25pIjoiZ3JwYy5leGFtcGxlLmNvbSIsInBhdGgiOiJteVNlcnZpY2VOYW1lIiwicHMiOiJNeVZNZXNzR1JQQyJ9`\n' +
        '• VLESS WS: `vless://uuid@example.com:443?security=tls&type=ws&path=/vless&sni=example.com#MyVlessWS`\n' +
        '• VLESS gRPC: `vless://uuid@example.com:443?security=tls&type=grpc&serviceName=myGrpcService&sni=example.com#MyVlessGRPC`\n' +
        '• Trojan WS: `trojan://password@example.com:443?security=tls&type=ws&path=/trojan&sni=example.com#MyTrojanWS`\n' +
        '• Trojan gRPC: `trojan://password@example.com:443?security=tls&type=grpc&serviceName=myGrpcService&sni=example.com#MyTrojanGRPC`',
        { parse_mode: 'Markdown' }
    );
});

// Handler for any text message received
bot.on('text', async (ctx) => {
    const text = ctx.message.text;
    console.log(`Message received from ${ctx.from.username || ctx.from.first_name}: ${text}`);

    try {
        const v2rayConfig = new V2RayConfig(text); // Automatically detect and parse the link

        let replyMessage = `Link asli Anda (${v2rayConfig.type.toUpperCase()} - Network: ${v2rayConfig.config.network || 'N/A'}):\n<code>${text}</code>\n\n---\n`;

        // Display conversion based on the input link type
        switch (v2rayConfig.type) {
            case 'vmess':
                const clashVmessYaml = v2rayConfig.toClashVmessYaml();
                replyMessage += `<b>Konversi ke Clash YAML (VMess Proxy):</b>\n<pre>${clashVmessYaml}</pre>`;
                break;

            case 'vless':
                const clashVlessYaml = v2rayConfig.toClashVlessYaml();
                replyMessage += `<b>Konversi ke Clash YAML (VLESS Proxy):</b>\n<pre>${clashVlessYaml}</pre>`;
                break;

            case 'trojan':
                const clashTrojanYaml = v2rayConfig.toClashTrojanYaml();
                replyMessage += `<b>Konversi ke Clash YAML (Trojan Proxy):</b>\n<pre>${clashTrojanYaml}</pre>`;
                break;

            default:
                replyMessage = 'Tipe link tidak dikenali. Silakan coba lagi dengan link VMess, VLESS, atau Trojan yang valid.';
                break;
        }

        await ctx.replyWithHTML(replyMessage);
        console.log('Conversion successful and reply sent.');

    } catch (error) {
        console.error(`Failed to convert link: ${error.message}`);
        await ctx.reply(
            `Maaf, ada kesalahan saat memproses link Anda:\n\n${error.message}\n\nPastikan link yang Anda berikan valid dan lengkap.`
        );
    }
});

// Activate the bot
bot.launch()
    .then(() => {
        console.log('Telegram bot is running...');
    })
    .catch((err) => {
        console.error('Failed to launch bot:', err);
    });

// Enable graceful stop on SIGINT (Ctrl+C) or SIGTERM signals
process.once('SIGINT', () => {
    bot.stop('SIGINT');
    console.log('Bot stopped (SIGINT).');
});
process.once('SIGTERM', () => {
    bot.stop('SIGTERM');
    console.log('Bot stopped (SIGTERM).');
});
