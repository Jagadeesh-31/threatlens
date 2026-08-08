"""
geoip.py — Free GeoIP lookup for ThreatLens.

Uses the free ip-api.com endpoint (no API key needed, rate-limited
to 45 req/min) to resolve source IPs to approximate lat/lon for
map visualization. Results are cached to avoid repeat lookups.
"""

import requests
import time
import json
import os
import shutil
from pathlib import Path

DEFAULT_CACHE_PATH = Path(__file__).resolve().parent.parent / "data" / "geoip_cache.json"


def _get_cache_path() -> Path:
    if os.environ.get("VERCEL") or not os.access(DEFAULT_CACHE_PATH.parent, os.W_OK):
        tmp_cache = Path("/tmp/geoip_cache.json")
        if not tmp_cache.exists() and DEFAULT_CACHE_PATH.exists():
            try:
                os.makedirs("/tmp", exist_ok=True)
                shutil.copy(DEFAULT_CACHE_PATH, tmp_cache)
            except Exception:
                pass
        return tmp_cache
    return DEFAULT_CACHE_PATH


def _load_cache() -> dict:
    cache_path = _get_cache_path()
    if cache_path.exists():
        try:
            return json.loads(cache_path.read_text())
        except Exception:
            pass
    return {}


def _save_cache(cache: dict) -> None:
    try:
        cache_path = _get_cache_path()
        cache_path.write_text(json.dumps(cache, indent=2))
    except Exception:
        pass


def lookup_ip(ip: str, cache: dict = None) -> dict | None:
    """
    Look up a single IP's geolocation. Returns None for private/reserved
    IPs (which won't resolve) or on lookup failure.
    """
    if cache is None:
        cache = _load_cache()

    if ip in cache:
        return cache[ip]

    # skip private/reserved ranges — they won't resolve anyway
    if ip.startswith(("192.168.", "10.", "172.16.", "127.")):
        return None

    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            result = {
                "lat": data["lat"],
                "lon": data["lon"],
                "city": data.get("city", "Unknown"),
                "country": data.get("country", "Unknown"),
            }
            cache[ip] = result
            _save_cache(cache)
            time.sleep(1.5)  # stay under free rate limit
            return result
    except requests.RequestException:
        pass

    cache[ip] = None
    _save_cache(cache)
    return None


def enrich_ips(ip_list: list[str]) -> dict:
    """Look up multiple IPs at once, returning {ip: {lat, lon, city, country}}."""
    cache = _load_cache()
    results = {}
    for ip in set(ip_list):
        result = lookup_ip(ip, cache)
        if result:
            results[ip] = result
    return results


if __name__ == "__main__":
    test_ips = ["203.0.113.45", "198.51.100.23", "8.8.8.8"]
    for ip in test_ips:
        print(ip, "->", lookup_ip(ip))
