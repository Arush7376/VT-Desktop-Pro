import os
import re
import base64
import hashlib
import ipaddress
from urllib.parse import urlparse

# Domain validation regex: labels separated by dots, 2+ char TLD
DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)


def detect_ioc(input_str: str) -> dict:
    """
    Intelligent Indicator of Compromise (IOC) Detector.
    
    Parses and classifies input into one of the supported IOC types:
    - FILE (Local existing readable file)
    - MD5 (32-char hex hash)
    - SHA1 (40-char hex hash)
    - SHA256 (64-char hex hash)
    - IPV4 (IPv4 address)
    - IPV6 (IPv6 address)
    - URL (Web URL)
    - DOMAIN (Domain name)
    - UNKNOWN (Unrecognized / invalid format)

    Returns a structured dictionary:
    {
        "type": str,
        "value": str,
        "valid": bool,
        "error": str or None,
        "hashes": dict or None (contains md5, sha1, sha256 for FILE),
        "vt_endpoint": str or None,
        "is_file": bool
    }
    """
    if not input_str or not isinstance(input_str, str):
        return {
            "type": "UNKNOWN",
            "value": "",
            "valid": False,
            "error": "Input is empty or invalid type.",
            "hashes": None,
            "vt_endpoint": None,
            "is_file": False
        }

    val = input_str.strip()
    if not val:
        return {
            "type": "UNKNOWN",
            "value": "",
            "valid": False,
            "error": "Input string is empty.",
            "hashes": None,
            "vt_endpoint": None,
            "is_file": False
        }

    # 1. Local File Check
    clean_path = val.strip('"\'')
    if os.path.exists(clean_path):
        if not os.path.isfile(clean_path):
            return {
                "type": "FILE",
                "value": clean_path,
                "valid": False,
                "error": "Target exists but is a directory, not a file.",
                "hashes": None,
                "vt_endpoint": None,
                "is_file": True
            }

        if not os.access(clean_path, os.R_OK):
            return {
                "type": "FILE",
                "value": clean_path,
                "valid": False,
                "error": "File exists but is not readable (Permission Denied).",
                "hashes": None,
                "vt_endpoint": None,
                "is_file": True
            }

        try:
            md5_h = hashlib.md5()
            sha1_h = hashlib.sha1()
            sha256_h = hashlib.sha256()

            with open(clean_path, "rb") as f:
                while chunk := f.read(65536):
                    md5_h.update(chunk)
                    sha1_h.update(chunk)
                    sha256_h.update(chunk)

            sha256_str = sha256_h.hexdigest()
            return {
                "type": "FILE",
                "value": os.path.abspath(clean_path),
                "valid": True,
                "error": None,
                "hashes": {
                    "md5": md5_h.hexdigest(),
                    "sha1": sha1_h.hexdigest(),
                    "sha256": sha256_str
                },
                "vt_endpoint": f"files/{sha256_str}",
                "is_file": True
            }
        except Exception as e:
            return {
                "type": "FILE",
                "value": clean_path,
                "valid": False,
                "error": f"Error reading file: {str(e)}",
                "hashes": None,
                "vt_endpoint": None,
                "is_file": True
            }

    # 2. Hash Check (MD5: 32, SHA1: 40, SHA256: 64 hex characters)
    if re.match(r'^[a-fA-F0-9]+$', val):
        hex_len = len(val)
        hash_type = None
        if hex_len == 32:
            hash_type = "MD5"
        elif hex_len == 40:
            hash_type = "SHA1"
        elif hex_len == 64:
            hash_type = "SHA256"

        if hash_type:
            return {
                "type": hash_type,
                "value": val.lower(),
                "valid": True,
                "error": None,
                "hashes": None,
                "vt_endpoint": f"files/{val.lower()}",
                "is_file": False
            }

    # 3. IP Address Check (IPv4 / IPv6)
    try:
        ip_obj = ipaddress.ip_address(val)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return {
                "type": "IPV4",
                "value": str(ip_obj),
                "valid": True,
                "error": None,
                "hashes": None,
                "vt_endpoint": f"ip_addresses/{ip_obj}",
                "is_file": False
            }
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            return {
                "type": "IPV6",
                "value": str(ip_obj),
                "valid": True,
                "error": None,
                "hashes": None,
                "vt_endpoint": f"ip_addresses/{ip_obj}",
                "is_file": False
            }
    except ValueError:
        pass

    # 4. URL Check
    is_url = False
    target_url = val
    if val.lower().startswith(("http://", "https://", "ftp://")):
        is_url = True
    elif val.lower().startswith("www."):
        is_url = True
        target_url = "http://" + val
    elif "/" in val and not val.startswith("/") and not val.startswith("\\"):
        parts = val.split("/", 1)
        host = parts[0]
        if DOMAIN_REGEX.match(host) or _is_ip(host):
            is_url = True
            target_url = "http://" + val

    if is_url:
        parsed = urlparse(target_url)
        if parsed.netloc:
            url_b64 = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
            return {
                "type": "URL",
                "value": target_url,
                "valid": True,
                "error": None,
                "hashes": None,
                "vt_endpoint": f"urls/{url_b64}",
                "is_file": False
            }

    # 5. Domain Check
    if DOMAIN_REGEX.match(val):
        return {
            "type": "DOMAIN",
            "value": val.lower(),
            "valid": True,
            "error": None,
            "hashes": None,
            "vt_endpoint": f"domains/{val.lower()}",
            "is_file": False
        }

    # 6. Fallback / Unrecognized
    return {
        "type": "UNKNOWN",
        "value": val,
        "valid": False,
        "error": "Unrecognized IOC format. Please provide a valid File Path, Hash (MD5/SHA1/SHA256), IP, Domain, or URL.",
        "hashes": None,
        "vt_endpoint": None,
        "is_file": False
    }


def _is_ip(val: str) -> bool:
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False
