#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import base64
import json
import os
import sys
import urllib.parse

import yaml

def _add_padding(value):
    return value + '=' * (-len(value) % 4)

def _sanitize_url(url):
    return url.replace('&amp;', '&').strip()

def _parse_query(query):
    params = urllib.parse.parse_qs(query, keep_blank_values=True)
    return {k: v[-1] if v else '' for k, v in params.items()}

def _bool_param(val):
    if val is None:
        return None
    return str(val).lower() in ('1', 'true', 'yes', 'on')

def _split_list(val):
    if not val:
        return []
    return [v.strip() for v in str(val).split(',') if v.strip()]

def _get_param(params, *keys):
    for key in keys:
        if key in params and params[key] != '':
            return params[key]
    return None

def _clean(obj):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            v = _clean(v)
            if v is None:
                continue
            if v == {} or v == []:
                continue
            out[k] = v
        return out
    if isinstance(obj, list):
        return [v for v in (_clean(i) for i in obj) if v not in (None, {}, [])]
    return obj

def _apply_tls_fields(proxy, params, servername_key):
    security = (params.get('security') or params.get('tls') or '').lower()
    sni = _get_param(params, 'sni', 'peer', 'servername', 'serverName')
    allow_insecure = _bool_param(_get_param(params, 'allowInsecure', 'insecure'))
    alpn = _split_list(_get_param(params, 'alpn'))
    client_fp = _get_param(params, 'fp', 'client-fingerprint')
    pbk = _get_param(params, 'pbk', 'public-key', 'public_key')
    sid = _get_param(params, 'sid', 'short-id', 'short_id')

    tls_enabled = False
    if security in ('tls', 'reality', 'xtls'):
        tls_enabled = True
    elif sni:
        tls_enabled = True

    if tls_enabled:
        proxy['tls'] = True
        if sni:
            proxy[servername_key] = sni
        if allow_insecure is not None:
            proxy['skip-cert-verify'] = bool(allow_insecure)
        if alpn:
            proxy['alpn'] = alpn
        if client_fp:
            proxy['client-fingerprint'] = client_fp
        if pbk or sid:
            proxy['reality-opts'] = {
                'public-key': pbk or '',
                'short-id': sid or ''
            }

def _apply_transport(proxy, transport, params):
    if not transport or transport == 'tcp':
        return
    proxy['network'] = transport
    if transport == 'ws':
        path = _get_param(params, 'path') or '/'
        host = _get_param(params, 'host', 'hostHeader', 'ws-host')
        ws_opts = {'path': path}
        if host:
            ws_opts['headers'] = {'Host': host}
        proxy['ws-opts'] = ws_opts
        return
    if transport == 'grpc':
        service = _get_param(params, 'serviceName', 'service_name', 'grpc-service-name')
        if service:
            proxy['grpc-opts'] = {'grpc-service-name': service}
        return
    if transport == 'h2':
        path = _get_param(params, 'path') or '/'
        host = _split_list(_get_param(params, 'host'))
        h2_opts = {'path': path}
        if host:
            h2_opts['host'] = host
        proxy['h2-opts'] = h2_opts
        return
    if transport == 'http':
        path = _get_param(params, 'path')
        if path:
            proxy['http-opts'] = {'path': [path]}

def _parse_vmess(url):
    payload = url[len('vmess://'):]
    payload = _add_padding(payload)
    try:
        decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
        data = json.loads(decoded)
    except Exception as exc:
        raise ValueError(f'vmess decode failed: {exc}') from exc

    server = data.get('add')
    port = int(data.get('port', 0)) if data.get('port') else 0
    uuid = data.get('id')
    if not server or not port or not uuid:
        raise ValueError('vmess missing server/port/uuid')

    proxy = {
        'name': 'probe',
        'type': 'vmess',
        'server': server,
        'port': port,
        'uuid': uuid,
        'alterId': int(data.get('aid', 0) or 0),
        'cipher': data.get('scy') or 'auto',
        'udp': True
    }

    params = {
        'security': data.get('tls') or data.get('security'),
        'sni': data.get('sni') or data.get('servername'),
        'alpn': data.get('alpn'),
        'allowInsecure': data.get('allowInsecure'),
        'fp': data.get('fp')
    }

    transport_type = (data.get('net') or '').lower()
    if transport_type:
        params.update({'type': transport_type, 'path': data.get('path'), 'host': data.get('host')})

    _apply_tls_fields(proxy, params, 'servername')
    _apply_transport(proxy, transport_type, params)
    return proxy

def _parse_vless(url):
    parsed = urllib.parse.urlparse(url)
    params = _parse_query(parsed.query)
    uuid = urllib.parse.unquote(parsed.username or '')
    server = parsed.hostname
    port = parsed.port or 443
    if not uuid or not server:
        raise ValueError('vless missing uuid/server')

    proxy = {
        'name': 'probe',
        'type': 'vless',
        'server': server,
        'port': port,
        'uuid': uuid,
        'udp': True
    }

    flow = _get_param(params, 'flow')
    if flow:
        proxy['flow'] = flow

    encryption = _get_param(params, 'encryption')
    if encryption is not None:
        proxy['encryption'] = encryption

    packet_encoding = _get_param(params, 'packet-encoding', 'packetEncoding')
    if packet_encoding:
        proxy['packet-encoding'] = packet_encoding

    transport = (_get_param(params, 'type', 'transport', 'network') or '').lower()
    _apply_tls_fields(proxy, params, 'servername')
    _apply_transport(proxy, transport, params)
    return proxy

def _parse_trojan(url):
    parsed = urllib.parse.urlparse(url)
    params = _parse_query(parsed.query)
    password = urllib.parse.unquote(parsed.username or '')
    server = parsed.hostname
    port = parsed.port or 443
    if not password or not server:
        raise ValueError('trojan missing password/server')

    proxy = {
        'name': 'probe',
        'type': 'trojan',
        'server': server,
        'port': port,
        'password': password,
        'udp': True,
        'tls': True
    }

    _apply_tls_fields(proxy, params, 'sni')
    transport = (_get_param(params, 'type', 'transport', 'network') or '').lower()
    _apply_transport(proxy, transport, params)
    return proxy

def _parse_ss(url):
    payload = url[len('ss://'):]
    payload = payload.split('#', 1)[0]
    payload = payload.split('?', 1)[0]

    if '@' not in payload:
        payload = _add_padding(payload)
        decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
        payload = decoded

    if '@' not in payload:
        raise ValueError('ss missing userinfo')

    userinfo, server_info = payload.rsplit('@', 1)
    if ':' not in userinfo or ':' not in server_info:
        raise ValueError('ss invalid format')

    method, password = userinfo.split(':', 1)
    server, port = server_info.rsplit(':', 1)
    return {
        'name': 'probe',
        'type': 'ss',
        'server': server,
        'port': int(port),
        'cipher': method,
        'password': password,
        'udp': True
    }

def _parse_hysteria2(url):
    parsed = urllib.parse.urlparse(url)
    params = _parse_query(parsed.query)
    password = urllib.parse.unquote(parsed.username or '')
    server = parsed.hostname
    port = parsed.port or 443
    if not password or not server:
        raise ValueError('hysteria2 missing password/server')

    proxy = {
        'name': 'probe',
        'type': 'hysteria2',
        'server': server,
        'port': port,
        'password': password,
        'udp': True
    }

    sni = _get_param(params, 'sni')
    if sni:
        proxy['sni'] = sni
    allow_insecure = _bool_param(_get_param(params, 'allowInsecure', 'insecure'))
    if allow_insecure is not None:
        proxy['skip-cert-verify'] = bool(allow_insecure)
    alpn = _split_list(_get_param(params, 'alpn'))
    if alpn:
        proxy['alpn'] = alpn
    client_fp = _get_param(params, 'fp', 'client-fingerprint')
    if client_fp:
        proxy['client-fingerprint'] = client_fp
    obfs = _get_param(params, 'obfs')
    if obfs:
        proxy['obfs'] = obfs
    obfs_password = _get_param(params, 'obfs-password', 'obfs_password')
    if obfs_password:
        proxy['obfs-password'] = obfs_password
    return proxy

def build_proxy(url):
    url = _sanitize_url(url)
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme == 'vmess':
        return _parse_vmess(url)
    if scheme == 'vless':
        return _parse_vless(url)
    if scheme == 'trojan':
        return _parse_trojan(url)
    if scheme == 'ss':
        return _parse_ss(url)
    if scheme == 'hysteria2':
        return _parse_hysteria2(url)
    raise ValueError(f'unsupported protocol: {scheme}')

def build_config(proxy, mixed_port, log_level):
    return _clean({
        'mixed-port': mixed_port,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': log_level,
        'proxies': [proxy],
        'proxy-groups': [
            {'name': 'Proxy', 'type': 'select', 'proxies': [proxy['name']]}
        ],
        'rules': ['MATCH,Proxy']
    })

def main():
    parser = argparse.ArgumentParser(description='Generate mihomo config from probe_head.json')
    parser.add_argument('--probe-json', default='runtime/probe_head.json')
    parser.add_argument('--output', default='runtime/mihomo-probe.yaml')
    parser.add_argument('--mixed-port', type=int, default=7892)
    parser.add_argument('--log-level', default='info')
    args = parser.parse_args()

    if not os.path.exists(args.probe_json):
        raise SystemExit(f'probe json not found: {args.probe_json}')

    with open(args.probe_json, 'r', encoding='utf-8') as f:
        data = json.load(f)

    node = data.get('node', data)
    if isinstance(node, dict):
        url = node.get('url')
    else:
        url = node

    if not url:
        raise SystemExit('probe json missing node url')

    proxy = build_proxy(url)
    config = build_config(proxy, args.mixed_port, args.log_level)
    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)

    print(args.output)

if __name__ == '__main__':
    main()
