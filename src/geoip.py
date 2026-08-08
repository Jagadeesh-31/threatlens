"""
geoip.py — Free GeoIP lookup for ThreatLens.

Uses the free ip-api.com endpoint (no API key needed, rate-limited
to 45 req/min) to resolve source IPs to approximate lat/lon for
map visualization. Results are cached to avoid repeat lookups.
"""

import requests
import time
import json
from pathlib import Path

CACHE_PATH = Path(__file__).resolve().parent.parent / "data" / "geoip_cache.json"


def _load_cache() -> dict:
    if CACHE_PATH.exists():
        return json.loads(CACHE_PATH.read_text())
    return {}


def _save_cache(cache: dict) -> None:
    CACHE_PATH.write_text(json.dumps(cache, indent=2))


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
