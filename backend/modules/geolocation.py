import os
import geoip2.database
import geoip2.errors

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
CITY_DB_PATH = os.path.join(DATA_DIR, 'GeoLite2-City.mmdb')
ASN_DB_PATH = os.path.join(DATA_DIR, 'GeoLite2-ASN.mmdb')

city_reader = None
asn_reader = None

# Initialize readers globally to save overhead, if files exist
if os.path.exists(CITY_DB_PATH):
    city_reader = geoip2.database.Reader(CITY_DB_PATH)

if os.path.exists(ASN_DB_PATH):
    asn_reader = geoip2.database.Reader(ASN_DB_PATH)

# A static list of common cloud/VPN providers that standard emails shouldn't originate directly from
KNOWN_HOSTING_PROVIDERS = [
    "digitalocean", "amazon", "aws", "ovh", "m247", "choopa", "hetzner", 
    "linode", "vultr", "alibaba", "tencent", "google cloud", "azure", "microsoft"
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
            print(f"GeoIP City Error for {ip}: {e}")

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
            print(f"GeoIP ASN Error for {ip}: {e}")

    return result
