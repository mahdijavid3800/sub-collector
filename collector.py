import base64
import json
import logging
import os
import re
import urllib.request
import urllib.error
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def is_valid_vless_url(url: str) -> bool:
    if not url or not url.startswith('vless://'):
        return False
    pattern = r'^vless://[a-f0-9\-]{36}@[a-zA-Z0-9\.\-]+:\d+.*$'
    return bool(re.match(pattern, url))


def fetch_and_decode(url: str) -> list[str]:
    """دریافت و دکود کردن محتوای لینک ساب"""
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'},
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode('utf-8').strip()
            try:
                # تلاش برای دکود Base64 (با در نظر گرفتن padding)
                padded = content + '=' * (-len(content) % 4)
                decoded = base64.b64decode(padded).decode('utf-8')
                logger.info(f'Successfully decoded base64 content from {url}')
                return decoded.splitlines()
            except Exception:
                logger.info(f'Content from {url} is plain text (not base64)')
                return content.splitlines()
    except urllib.error.URLError as e:
        logger.error(f'Network error fetching {url}: {e}')
        return []
    except Exception as e:
        logger.error(f'Unexpected error fetching {url}: {e}')
        return []


def parse_vless_to_outbound(vless_url: str, tag_name: str) -> Optional[dict]:
    """تبدیل لینک vless:// به آبجکت outbound در Xray"""
    try:
        if not is_valid_vless_url(vless_url):
            logger.warning(f'Invalid VLESS URL format: {vless_url[:50]}...')
            return None

        parsed = urlparse(vless_url)
        if parsed.scheme != 'vless':
            return None

        uuid = parsed.username
        address = parsed.hostname
        port = parsed.port or 443

        if not uuid or not address:
            logger.warning(f'Missing UUID or address in URL: {vless_url[:50]}...')
            return None

        params = parse_qs(parsed.query)
        network = params.get('type', ['tcp'])[0]
        security = params.get('security', ['none'])[0]
        path = unquote(params.get('path', ['/'])[0])
        host = params.get('host', [''])[0]
        sni = params.get('sni', [''])[0]
        fp = params.get('fp', ['chrome'])[0]
        alpn_raw = params.get('alpn', [''])[0]
        alpn = [x.strip() for x in alpn_raw.split(',') if x.strip()] if alpn_raw else []

        try:
            port_num = int(port)
            if not (1 <= port_num <= 65535):
                logger.warning(f'Invalid port number: {port}')
                return None
        except ValueError:
            logger.warning(f'Port is not a number: {port}')
            return None

        outbound: dict = {
            'mux': {'concurrency': -1, 'enabled': False},
            'protocol': 'vless',
            'settings': {
                'vnext': [
                    {
                        'address': address,
                        'port': port_num,
                        'users': [{'encryption': 'none', 'id': uuid, 'level': 8}],
                    }
                ]
            },
            'streamSettings': {'network': network},
            'tag': tag_name,
        }

        if network == 'ws':
            ws_settings: dict = {'headers': {}}
            if host:
                ws_settings['headers']['Host'] = host
            if path:
                ws_settings['path'] = path
            outbound['streamSettings']['wsSettings'] = ws_settings
        elif network == 'grpc':
            grpc_service_name = params.get('serviceName', [''])[0]
            if grpc_service_name:
                outbound['streamSettings']['grpcSettings'] = {
                    'serviceName': grpc_service_name
                }

        if security == 'tls':
            outbound['streamSettings']['security'] = 'tls'
            tls_settings: dict = {'allowInsecure': False, 'show': False}
            if sni:
                tls_settings['serverName'] = sni
            else:
                tls_settings['serverName'] = address
            if fp:
                tls_settings['fingerprint'] = fp
            if alpn:
                tls_settings['alpn'] = alpn
            outbound['streamSettings']['tlsSettings'] = tls_settings
        elif security == 'reality':
            outbound['streamSettings']['security'] = 'reality'
            reality_settings: dict = {
                'show': False,
                'publicKey': params.get('pbk', [''])[0],
                'shortId': params.get('sid', [''])[0],
            }
            if sni:
                reality_settings['serverName'] = sni
            else:
                reality_settings['serverName'] = address
            if fp:
                reality_settings['fingerprint'] = fp
            outbound['streamSettings']['realitySettings'] = reality_settings

        return outbound
    except Exception as e:
        logger.error(f'Error parsing link {vless_url[:50]}...: {e}')
        return None


def generate_full_json_config(
    outbound_proxies: list[dict],
    remarks: str = 'javidsub Intelligent Selection'
) -> dict:
    """تولید ساختار کامل JSON نهایی"""
    base_config: dict = {
        'dns': {
            'hosts': {
                'domain:googleapis.cn': 'googleapis.com',
                'dns.alidns.com': ['223.5.5.5', '223.6.6.6', '2400:3200::1', '2400:3200:baba::1'],
                'one.one.one.one': ['1.1.1.1', '1.0.0.1', '2606:4700:4700::1111', '2606:4700:4700::1001'],
                'dns.cloudflare.com': ['104.16.132.229', '104.16.133.229', '2606:4700::6810:84e5', '2606:4700::6810:85e5'],
                'dns.google': ['8.8.8.8', '8.8.4.4', '2001:4860:4860::8888', '2001:4860:4860::8844'],
            },
            'servers': [
                '1.1.1.1',
                {'address': '1.1.1.1', 'domains': ['geosite:google']},
                {
                    'address': '223.5.5.5',
                    'domains': ['domain:alidns.com', 'domain:doh.pub', 'domain:dot.pub', 'geosite:cn'],
                    'expectIPs': ['geoip:cn'],
                    'skipFallback': True,
                    'tag': 'domestic-dns',
                },
            ],
            'tag': 'dns-module',
        },
        'inbounds': [
            {
                'listen': '127.0.0.1',
                'port': 10808,
                'protocol': 'socks',
                'settings': {'auth': 'noauth', 'udp': True, 'userLevel': 8},
                'sniffing': {'destOverride': ['http', 'tls'], 'enabled': True, 'routeOnly': False},
                'tag': 'socks',
            }
        ],
        'log': {'loglevel': 'warning'},
        'observatory': {
            'enableConcurrency': True,
            'probeInterval': '3m',
            'probeUrl': 'https://www.gstatic.com/generate_204',
            'subjectSelector': ['proxy-'],
        },
        'outbounds': [],
        'policy': {
            'levels': {'8': {'connIdle': 300, 'downlinkOnly': 1, 'handshake': 4, 'uplinkOnly': 1}},
            'system': {'statsOutboundDownlink': True, 'statsOutboundUplink': True},
        },
        'remarks': remarks,
        'routing': {
            'balancers': [{'selector': ['proxy-'], 'strategy': {'type': 'leastPing'}, 'tag': 'proxy-round'}],
            'domainStrategy': 'AsIs',
            'rules': [
                {'network': 'udp', 'outboundTag': 'block', 'port': '443', 'type': 'field'},
                {'balancerTag': 'proxy-round', 'domain': ['geosite:google'], 'type': 'field'},
                {'ip': ['geoip:private'], 'outboundTag': 'direct', 'type': 'field'},
                {'domain': ['geosite:private'], 'outboundTag': 'direct', 'type': 'field'},
                {'ip': ['geoip:cn'], 'outboundTag': 'direct', 'type': 'field'},
                {'domain': ['geosite:cn'], 'outboundTag': 'direct', 'type': 'field'},
                {'inboundTag': ['domestic-dns'], 'outboundTag': 'direct', 'type': 'field'},
                {'balancerTag': 'proxy-round', 'inboundTag': ['dns-module'], 'type': 'field'},
                {'balancerTag': 'proxy-round', 'network': 'tcp,udp', 'type': 'field'},
            ],
        },
        'stats': {},
    }

    base_config['outbounds'].extend(outbound_proxies)
    base_config['outbounds'].append({'protocol': 'freedom', 'settings': {'domainStrategy': 'UseIP'}, 'tag': 'direct'})
    base_config['outbounds'].append({'protocol': 'blackhole', 'settings': {'response': {'type': 'http'}}, 'tag': 'block'})

    return base_config


def save_raw_configs(filename: str, configs: list[str]) -> None:
    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(configs))
    logger.info(f'Saved raw configs to {filename}')


def save_final_json(filename: str, outbounds: list[dict], remarks: str) -> None:
    final_json_structure = generate_full_json_config(outbounds, remarks=remarks)
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(final_json_structure, f, ensure_ascii=False, indent=2)
    logger.info(f'Saved final JSON configuration to {filename}')


def main():
    """تابع اصلی برنامه"""
    raw_urls = os.environ.get('SUB_URLS', '')
    urls = [u.strip() for u in raw_urls.splitlines() if u.strip()]

    if not urls:
        logger.error('No URLs found in SUB_URLS environment variable!')
        return

    all_raw_configs: list[str] = []
    seen_urls_global: set[str] = set()

    # ۱. پردازش همه لینک‌ها و جمع‌آوری تمام کانفیگ‌ها
    for sub_index, url in enumerate(urls, start=1):
        logger.info(f'Processing subscription URL #{sub_index}: {url[:60]}...')
        lines = fetch_and_decode(url)

        for line in lines:
            line = line.strip()
            if is_valid_vless_url(line) and line not in seen_urls_global:
                seen_urls_global.add(line)
                all_raw_configs.append(line)

    if not all_raw_configs:
        logger.warning('No valid VLESS configurations found!')
        return

    # ۲. ذخیره فایل خام کلی (javidsub)
    save_raw_configs('javidsub', all_raw_configs)

    # ۳. تبدیل تمام لینک‌ها به Outbound
    parsed_outbounds_global: list[dict] = []
    for idx, link in enumerate(all_raw_configs, start=1):
        outbound = parse_vless_to_outbound(link, tag_name=f'proxy-{idx}')
        if outbound:
            parsed_outbounds_global.append(outbound)

    # ۴. ذخیره فایل نهایی کلی (final_sub.txt) - یک JSON معتبر با تمام کانفیگ‌ها
    if parsed_outbounds_global:
        save_final_json('final_sub.txt', parsed_outbounds_global, remarks='javidsub Intelligent Selection')


if __name__ == '__main__':
    main()
