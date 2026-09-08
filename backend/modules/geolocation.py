import logging
import os
import geoip2.database
import geoip2.errors

logger = logging.getLogger("traceshield.geolocation")

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
CITY_DB_PATH = os.path.join(DATA_DIR, 'GeoLite2-City.mmdb')
ASN_DB_PATH = os.path.join(DATA_DIR, 'GeoLite2-ASN.mmdb')

city_reader = None
asn_reader = None

# Initialize readers globally to save overhead, if files exist
# Wrapped in try/except: a corrupted or half-downloaded .mmdb file can raise an
# exception at import time that would kill the FastAPI process on startup.
if os.path.exists(CITY_DB_PATH):
    try:
        city_reader = geoip2.database.Reader(CITY_DB_PATH)
    except Exception as _e:
        logger.error("Failed to open GeoLite2-City.mmdb: %s", _e)

if os.path.exists(ASN_DB_PATH):
    try:
        asn_reader = geoip2.database.Reader(ASN_DB_PATH)
    except Exception as _e:
        logger.error("Failed to open GeoLite2-ASN.mmdb: %s", _e)

# Cloud hosting and VPN providers that standard corporate/banking email
# should NOT originate from. Residential ISPs (BSNL, Airtel, JIO etc.)
# are explicitly EXCLUDED to avoid false positives on user-sent mail.
KNOWN_HOSTING_PROVIDERS = [
    # Major public clouds
    "amazon", "amazonaws", "aws",
    "google cloud", "googlecloud",
    "microsoft azure", "azure",
    "alibaba cloud", "alibaba",
    "tencent cloud", "tencent",
    # VPS / dedicated hosting
    "digitalocean", "linode", "vultr", "hetzner", "ovh",
    "choopa", "m247", "psychz", "codero", "liquidweb",
    # Bulletproof / grey-market hosters
    "frantech", "2connect", "serverius",
    # CDN/proxy used as origin obfuscation
    "cloudflare",
]

def _is_known_hosting(org_name: str) -> bool:
    if not org_name:
        return False
    org_lower = org_name.lower()
    for provider in KNOWN_HOSTING_PROVIDERS:
        if provider in org_lower:
            return True
    return False

def geolocate_ip(ip: str) -> dict:
    """
    Looks up the provided IP address in the local MaxMind databases.
    Returns country, city, ISP, lat/long, and hosting flag.
    Lat/long is required by the frontend TraceMap (Leaflet.js).
    """
    result = {
        "origin_ip": ip,
        "origin_country": "Unknown",
        "origin_city": "Unknown",
        "origin_isp": "Unknown",
        "latitude": None,
        "longitude": None,
        "is_known_vpn_or_hosting": False
    }

    if not ip:
        return result

    # 1. Check City/Country/Coordinates Database
    if city_reader:
        try:
            response = city_reader.city(ip)
            if response.country.name:
                result["origin_country"] = response.country.name
            if response.city.name:
                result["origin_city"] = response.city.name
            if response.location.latitude is not None:
                result["latitude"] = response.location.latitude
                result["longitude"] = response.location.longitude
        except geoip2.errors.AddressNotFoundError:
            pass
        except Exception as e:
            logger.warning("GeoIP City Error for %s: %s", ip, e)

    # 2. Check ASN/ISP Database
    if asn_reader:
        try:
            response = asn_reader.asn(ip)
            if response.autonomous_system_organization:
                org_name = response.autonomous_system_organization
                result["origin_isp"] = org_name
                result["is_known_vpn_or_hosting"] = _is_known_hosting(org_name)
        except geoip2.errors.AddressNotFoundError:
            pass
        except Exception as e:
            logger.warning("GeoIP ASN Error for %s: %s", ip, e)

    # 3. Fallback / Enhancement with Live API if city is unknown or coords are generic
    if result["origin_city"] == "Unknown":
        try:
            import urllib.request
            import json
            req = urllib.request.Request(f"http://ip-api.com/json/{ip}", headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=3) as response:
                api_resp = json.loads(response.read().decode())
                
            if api_resp.get("status") == "success":
                result["origin_country"] = api_resp.get("country", result["origin_country"])
                result["origin_city"] = api_resp.get("city", result["origin_city"])
                if "lat" in api_resp and "lon" in api_resp:
                    result["latitude"] = api_resp["lat"]
                    result["longitude"] = api_resp["lon"]
                if result["origin_isp"] == "Unknown":
                    isp_name = api_resp.get("isp") or api_resp.get("org")
                    result["origin_isp"] = isp_name or "Unknown"
                    result["is_known_vpn_or_hosting"] = _is_known_hosting(isp_name)
        except Exception as e:
            logger.warning("Live IP API fallback error for %s: %s", ip, e)

    return result
