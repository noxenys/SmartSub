#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import json
import os
import shutil
import stat
import tarfile
import tempfile
import urllib.request
import zipfile
import gzip

API_URL = 'https://api.github.com/repos/MetaCubeX/mihomo/releases'

def _download_json(url):
    with urllib.request.urlopen(url) as resp:
        return json.loads(resp.read().decode('utf-8'))

def _download_file(url, path):
    with urllib.request.urlopen(url) as resp, open(path, 'wb') as f:
        shutil.copyfileobj(resp, f)

def _pick_asset(release, keyword):
    for asset in release.get('assets', []):
        name = asset.get('name', '')
        if keyword in name and 'linux' in name and 'amd64' in name:
            return asset.get('browser_download_url')
    return None

def _find_binary(root):
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            if name == 'mihomo' or name == 'clash':
                return os.path.join(dirpath, name)
    return None

def _extract_archive(archive_path, dest_dir):
    if archive_path.endswith('.tar.gz') or archive_path.endswith('.tgz'):
        with tarfile.open(archive_path, 'r:gz') as tar:
            tar.extractall(dest_dir)
        return
    if archive_path.endswith('.zip'):
        with zipfile.ZipFile(archive_path, 'r') as zf:
            zf.extractall(dest_dir)
        return
    if archive_path.endswith('.gz'):
        output_path = os.path.join(dest_dir, 'mihomo')
        with gzip.open(archive_path, 'rb') as src, open(output_path, 'wb') as dst:
            shutil.copyfileobj(src, dst)
        return

def _default_cache_dir():
    return os.path.join(os.path.expanduser('~'), '.cache', 'smartsub')

def _cache_path(cache_dir, version, arch):
    os.makedirs(cache_dir, exist_ok=True)
    return os.path.join(cache_dir, f'mihomo-{version}-{arch}')

def main():
    parser = argparse.ArgumentParser(description='Download mihomo binary')
    parser.add_argument('--output', default='mihomo')
    parser.add_argument('--version', default='latest')
    parser.add_argument('--arch', default='linux-amd64')
    parser.add_argument('--cache-dir', default=None)
    args = parser.parse_args()

    output = os.path.abspath(args.output)
    if os.path.exists(output):
        print(output)
        return

    cache_dir = args.cache_dir or os.getenv('SMARTSUB_CACHE_DIR') or _default_cache_dir()
    cache_path = _cache_path(cache_dir, args.version, args.arch)
    if os.path.exists(cache_path):
        os.makedirs(os.path.dirname(output), exist_ok=True)
        shutil.copyfile(cache_path, output)
        os.chmod(output, os.stat(output).st_mode | stat.S_IEXEC)
        print(output)
        return

    if args.version == 'latest':
        release = _download_json(f'{API_URL}/latest')
    else:
        releases = _download_json(API_URL)
        release = None
        for item in releases:
            if item.get('tag_name') == args.version:
                release = item
                break
        if not release:
            raise SystemExit(f'Cannot find mihomo release: {args.version}')

    url = _pick_asset(release, args.arch)
    if not url:
        raise SystemExit(f'Cannot find asset for {args.arch}')

    with tempfile.TemporaryDirectory() as tmpdir:
        archive_name = os.path.basename(url)
        archive_path = os.path.join(tmpdir, archive_name)
        _download_file(url, archive_path)

        if archive_name.endswith(('.tar.gz', '.tgz', '.zip', '.gz')):
            _extract_archive(archive_path, tmpdir)
            binary = _find_binary(tmpdir)
            if not binary:
                raise SystemExit('mihomo binary not found in archive')
        else:
            binary = archive_path

        os.makedirs(os.path.dirname(output), exist_ok=True)
        shutil.copyfile(binary, output)
        os.chmod(output, os.stat(output).st_mode | stat.S_IEXEC)
        try:
            shutil.copyfile(output, cache_path)
            os.chmod(cache_path, os.stat(cache_path).st_mode | stat.S_IEXEC)
        except Exception:
            pass

    print(output)

if __name__ == '__main__':
    main()
