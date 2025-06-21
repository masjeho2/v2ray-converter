/**
 * @file index.js
 * @description Bot Telegram untuk mendeteksi jenis link V2Ray (VMess, VLESS, Trojan)
 * dan mengonversinya ke berbagai format Clash YAML, dimodifikasi untuk Cloudflare Workers.
 *
 * Menggunakan Telegraf dalam mode Webhook.
 * Variabel lingkungan (BOT_TOKEN) diakses melalui `env`.
 */

// Mengimpor kelas Telegraf dari pustaka telegraf
const { Telegraf } = require('telegraf');

// Variabel global untuk instance bot
let bot;

/**
 * Kelas V2RayConfig: Bertanggung jawab untuk mem-parsing berbagai jenis link V2Ray
 * (VMess, VLESS, Trojan) dan mengonversinya ke format Clash YAML yang relevan,
 * termasuk penanganan opsi network (WebSocket, gRPC).
 */
class V2RayConfig {
    /**
     * Konstruktor untuk V2RayConfig.
     * @param {string} link Link V2Ray (VMess, VLESS, atau Trojan) yang akan di-parse.
     */
    constructor(link) {
        this.originalLink = link;
        this.type = null; // Tipe protokol (vmess, vless, trojan)
        this.config = {}; // Objek untuk menyimpan properti konfigurasi yang di-parse

        this.parse(link);
    }

    /**
     * Mendeteksi tipe link dan memanggil parser yang sesuai.
     * @param {string} link Link V2Ray.
     * @throws {Error} Jika format link tidak valid atau tidak didukung.
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
            throw new Error("Tipe link V2Ray tidak didukung atau format tidak valid. Hanya VMess, VLESS, atau Trojan.");
        }
    }

    /**
     * Mem-parsing link VMess.
     * @param {string} link Link VMess.
     * @private
     */
    _parseVmess(link) {
        try {
            const base64Part = link.split('vmess://')[1];
            // Tambahkan padding jika diperlukan untuk Base64 yang benar
            const paddedBase64 = base64Part.length % 4 === 0 ? base64Part : base64Part + '='.repeat(4 - (base64Part.length % 4));
            // Gunakan Buffer dari Node.js compat
            const decoded = Buffer.from(paddedBase64, 'base64').toString('utf8');
            const jsonConfig = JSON.parse(decoded);

            this.config = {
                address: jsonConfig.add,
                port: jsonConfig.port,
                id: jsonConfig.id,
                alterId: jsonConfig.aid,
                network: jsonConfig.net,
                type: jsonConfig.type, // "none" atau lainnya
                tls: jsonConfig.tls === 'tls', // Ubah ke boolean
                sni: jsonConfig.sni || jsonConfig.add,
                ps: jsonConfig.ps,
                path: jsonConfig.path || '/', // path untuk ws/grpc
                host: jsonConfig.host || '', // host header untuk ws
                serviceName: jsonConfig.path || '', // Untuk gRPC, path seringkali serviceName
            };
        } catch (error) {
            throw new Error(`Gagal mem-parsing link VMess: ${error.message}.`);
        }
    }

    /**
     * Mem-parsing link VLESS.
     * @param {string} link Link VLESS.
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

            // Inisialisasi default
            this.config.tls = false;
            this.config.network = 'tcp';
            this.config.path = '/';
            this.config.host = '';
            this.config.sni = address;
            this.config.serviceName = ''; // Khusus untuk gRPC

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
                        case 'servicename': // Tangani parameter serviceName eksplisit untuk gRPC
                            this.config.serviceName = value;
                            break;
                        case 'flow':
                            this.config.flow = value;
                            break;
                    }
                });
            }
            // Jika network adalah gRPC tetapi serviceName tidak eksplisit, gunakan path
            if (this.config.network === 'grpc' && !this.config.serviceName) {
                this.config.serviceName = this.config.path;
            }
        } catch (error) {
            throw new Error(`Gagal mem-parsing link VLESS: ${error.message}.`);
        }
    }

    /**
     * Mem-parsing link Trojan.
     * @param {string} link Link Trojan.
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

            // Inisialisasi default
            this.config.tls = false;
            this.config.network = 'tcp';
            this.config.path = '/';
            this.config.host = '';
            this.config.sni = address;
            this.config.serviceName = ''; // Khusus untuk gRPC

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
                        case 'servicename': // Tangani parameter serviceName eksplisit untuk gRPC
                            this.config.serviceName = value;
                            break;
                    }
                });
            }
            // Jika network adalah gRPC tetapi serviceName tidak eksplisit, gunakan path
            if (this.config.network === 'grpc' && !this.config.serviceName) {
                this.config.serviceName = this.config.path;
            }
        } catch (error) {
            throw new Error(`Gagal mem-parsing link Trojan: ${error.message}.`);
        }
    }

    /**
     * Mengonversi konfigurasi yang di-parse ke format link VLESS.
     * Metode ini hanya relevan jika input aslinya VMess.
     * @returns {string} Link VLESS yang dikonversi.
     */
    toVlessLink() {
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
            // Untuk gRPC, path juga kadang digunakan sebagai serviceName, jadi tambahkan juga jika ada dan berbeda
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
     * Mengonversi konfigurasi yang di-parse ke format YAML Clash (tipe VMess).
     * @returns {string} Konfigurasi Clash YAML untuk VMess proxy.
     */
    toClashVmessYaml() {
        if (this.type !== 'vmess') {
            this.config.id = this.config.id || this.config.password;
            this.config.alterId = this.config.alterId || 0;
        }

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
     * Mengonversi konfigurasi yang di-parse ke format YAML Clash (tipe VLESS).
     * @returns {string} Konfigurasi Clash YAML untuk VLESS proxy.
     */
    toClashVlessYaml() {
        this.config.id = this.config.id || this.config.password;

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
     * Mengonversi konfigurasi yang di-parse ke format YAML Clash (tipe Trojan).
     * @returns {string} Konfigurasi Clash YAML untuk Trojan proxy.
     */
    toClashTrojanYaml() {
        this.config.password = this.config.password || this.config.id;

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


// Handler untuk permintaan HTTP yang masuk ke Worker
export default {
    async fetch(request, env, ctx) {
        // Inisialisasi bot jika belum ada.
        // `env` adalah objek yang berisi variabel lingkungan yang didefinisikan di Cloudflare.
        if (!bot) {
            if (!env.BOT_TOKEN) {
                // Log kesalahan dan kembalikan respons HTTP
                console.error('Error: BOT_TOKEN is not configured in Cloudflare Worker environment.');
                return new Response('Internal Server Error: BOT_TOKEN is missing.', { status: 500 });
            }
            bot = new Telegraf(env.BOT_TOKEN);

            // --- Handler Perintah Bot ---
            bot.start((ctx) => {
                ctx.reply(
                    'Halo! Kirimkan link V2Ray (VMess, VLESS, atau Trojan) untuk saya konversi ke berbagai format Clash YAML.\n\n' +
                    'Bot ini akan mendeteksi tipe network (WebSocket, gRPC, dll.) dan merefleksikannya dalam output.\n\n' +
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

            bot.on('text', async (ctx) => {
                const text = ctx.message.text;
                console.log(`Pesan diterima dari ${ctx.from.username || ctx.from.first_name}: ${text}`);

                try {
                    const v2rayConfig = new V2RayConfig(text); // Otomatis mendeteksi dan mem-parse link

                    let replyMessage = `Link asli Anda (${v2rayConfig.type.toUpperCase()} - Network: ${v2rayConfig.config.network || 'N/A'}):\n<code>${text}</code>\n\n---\n`;

                    // Tampilkan konversi berdasarkan tipe link input
                    switch (v2rayConfig.type) {
                        case 'vmess':
                            const vlessLink = v2rayConfig.toVlessLink();
                            const clashVmessYaml = v2rayConfig.toClashVmessYaml();
                            const clashVlessYamlFromVmess = v2rayConfig.toClashVlessYaml();
                            const clashTrojanYamlFromVmess = v2rayConfig.toClashTrojanYaml();

                            replyMessage += `<b>Konversi ke Link VLESS:</b>\n<code>${vlessLink}</code>\n\n---\n`;
                            replyMessage += `<b>Konversi ke Clash YAML (VMess Proxy):</b>\n<pre>${clashVmessYaml}</pre>\n\n---\n`;
                            replyMessage += `<b>Konversi ke Clash YAML (VLESS Proxy):</b>\n<pre>${clashVlessYamlFromVmess}</pre>\n\n---\n`;
                            replyMessage += `<b>Konversi ke Clash YAML (Trojan Proxy):</b>\n<pre>${clashTrojanYamlFromVmess}</pre>`;
                            break;

                        case 'vless':
                            const clashVlessYaml = v2rayConfig.toClashVlessYaml();
                            const clashTrojanYamlFromVless = v2rayConfig.toClashTrojanYaml();
                            const clashVmessYamlFromVless = v2rayConfig.toClashVmessYaml();

                            replyMessage += `<b>Konversi ke Clash YAML (VLESS Proxy):</b>\n<pre>${clashVlessYaml}</pre>\n\n---\n`;
                            replyMessage += `<b>Konversi ke Clash YAML (Trojan Proxy):</b>\n<pre>${clashTrojanYamlFromVless}</pre>\n\n---\n`;
                            replyMessage += `<b>Konversi ke Clash YAML (VMess Proxy):</b>\n<pre>${clashVmessYamlFromVless}</pre>`;
                            break;

                        case 'trojan':
                            const clashTrojanYaml = v2rayConfig.toClashTrojanYaml();
                            const clashVlessYamlFromTrojan = v2rayConfig.toClashVlessYaml();
                            const clashVmessYamlFromTrojan = v2rayConfig.toClashVmessYaml();

                            replyMessage += `<b>Konversi ke Clash YAML (Trojan Proxy):</b>\n<pre>${clashTrojanYaml}</pre>\n\n---\n`;
                            replyMessage += `<b>Konversi ke Clash YAML (VLESS Proxy):</b>\n<pre>${clashVlessYamlFromTrojan}</pre>\n\n---\n`;
                            replyMessage += `<b>Konversi ke Clash YAML (VMess Proxy):</b>\n<pre>${clashVmessYamlFromTrojan}</pre>`;
                            break;

                        default:
                            replyMessage = 'Tipe link tidak dikenali. Silakan coba lagi dengan link VMess, VLESS, atau Trojan yang valid.';
                            break;
                    }

                    await ctx.replyWithHTML(replyMessage);
                    console.log('Konversi berhasil dan balasan dikirim.');

                } catch (error) {
                    console.error(`Gagal mengonversi link: ${error.message}`);
                    await ctx.reply(
                        `Maaf, ada kesalahan saat memproses link Anda:\n\n${error.message}\n\nPastikan link yang Anda berikan valid dan lengkap.`
                    );
                }
            });
        }

        // Pastikan ini adalah permintaan POST dari Telegram Webhook
        if (request.method === 'POST') {
            // Telegraf akan memproses body request dan memicu handler yang sesuai
            const handleUpdate = bot.webhookCallback('/telegram-webhook'); // Sesuaikan path ini dengan yang Anda daftarkan di Telegram
            return handleUpdate(request);
        }

        // Jika ada permintaan selain POST ke root, atau permintaan GET, bisa kembalikan pesan informasi
        return new Response('Hello! This is a Telegram bot Cloudflare Worker. Please interact via Telegram.', { status: 200 });
    }
};
