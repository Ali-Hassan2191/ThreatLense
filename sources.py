# %%writefile sources.py
"""
sources.py
----------
All threat-intelligence source logic lives here.
"""

import base64
import ipaddress
import os
import re
import urllib.parse

import requests
import whois as whois_lib

try:
    import streamlit as st
except ImportError:
    st = None

REQUEST_TIMEOUT = 10


def _get_secret(key):
    if st is not None:
        try:
            if st.session_state.get(key):
                return st.session_state[key]
        except Exception:
            pass
        try:
            if key in st.secrets:
                return st.secrets[key]
        except Exception:
            pass
    return os.environ.get(key)


def normalize_target(target, target_type):
    if target is None:
        return ""
    cleaned = target.strip()
    if target_type == "URL":
        if cleaned and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", cleaned):
            cleaned = "https://" + cleaned
    if target_type == "Domain":
        cleaned = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", cleaned)
        cleaned = cleaned.rstrip("/")
    return cleaned


def validate_target(target, target_type):
    if not target:
        return False, "Please enter a value to analyze."
    if target_type == "IP Address":
        try:
            ipaddress.ip_address(target)
            return True, None
        except ValueError:
            return False, "That doesn't look like a valid IPv4 or IPv6 address."
    if target_type == "Domain":
        domain_pattern = re.compile(
            r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
            r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
        )
        if domain_pattern.match(target):
            return True, None
        return False, "That doesn't look like a valid domain (e.g. example.com)."
    if target_type == "URL":
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return True, None
        return False, "That doesn't look like a valid URL (e.g. https://example.com)."
    return False, "Unknown target type."


def _extract_domain_from_url(url):
    try:
        return urllib.parse.urlparse(url).hostname
    except Exception:
        return None


def _vt_headers():
    api_key = _get_secret("VIRUSTOTAL_API_KEY")
    if not api_key:
        return None
    return {"x-apikey": api_key}


def _vt_extract_stats(attributes):
    stats = attributes.get("last_analysis_stats", {}) or {}
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "timeout": stats.get("timeout", 0),
        "reputation": attributes.get("reputation"),
        "categories": attributes.get("categories", {}),
    }


def get_virustotal(target, target_type):
    source = "VirusTotal"
    headers = _vt_headers()
    if headers is None:
        return {"source": source, "status": "error", "data": {}, "error": "VirusTotal API key is not configured."}
    try:
        if target_type == "IP Address":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        elif target_type == "Domain":
            url = f"https://www.virustotal.com/api/v3/domains/{target}"
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        elif target_type == "URL":
            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            report_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            resp = requests.get(report_endpoint, headers=headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 404:
                submit = requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers, data={"url": target}, timeout=REQUEST_TIMEOUT,
                )
                if submit.status_code not in (200, 201):
                    return {"source": source, "status": "error", "data": {}, "error": f"VirusTotal submission failed (HTTP {submit.status_code})."}
                analysis_id = submit.json().get("data", {}).get("id")
                analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                analysis_resp = requests.get(analysis_url, headers=headers, timeout=REQUEST_TIMEOUT)
                if analysis_resp.status_code != 200:
                    return {"source": source, "status": "error", "data": {}, "error": "VirusTotal analysis could not be retrieved."}
                attrs = analysis_resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("stats", {})
                return {
                    "source": source, "status": "success",
                    "data": {
                        "note": "Newly submitted URL - scan just started, results may be partial.",
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "scan_status": attrs.get("status"),
                    },
                    "error": None,
                }
        else:
            return {"source": source, "status": "unsupported", "data": {}, "error": f"VirusTotal does not support target type '{target_type}'."}

        if resp.status_code == 401:
            return {"source": source, "status": "error", "data": {}, "error": "VirusTotal API key was rejected (unauthorized)."}
        if resp.status_code == 404:
            return {"source": source, "status": "success", "data": {"note": "No existing VirusTotal report found for this target."}, "error": None}
        if resp.status_code != 200:
            return {"source": source, "status": "error", "data": {}, "error": f"VirusTotal request failed (HTTP {resp.status_code})."}

        attributes = resp.json().get("data", {}).get("attributes", {})
        return {"source": source, "status": "success", "data": _vt_extract_stats(attributes), "error": None}

    except requests.exceptions.Timeout:
        return {"source": source, "status": "error", "data": {}, "error": "VirusTotal request timed out."}
    except requests.exceptions.RequestException as exc:
        return {"source": source, "status": "error", "data": {}, "error": f"VirusTotal request failed: {exc}"}
    except Exception as exc:
        return {"source": source, "status": "error", "data": {}, "error": f"Unexpected VirusTotal error: {exc}"}


def _whois_lookup(domain):
    record = whois_lib.whois(domain)

    def _first(value):
        if isinstance(value, list):
            return str(value[0]) if value else None
        return str(value) if value is not None else None

    return {
        "registrar": _first(record.get("registrar")),
        "created": _first(record.get("creation_date")),
        "expires": _first(record.get("expiration_date")),
        "updated": _first(record.get("updated_date")),
        "name_servers": record.get("name_servers") if record.get("name_servers") else None,
        "status": _first(record.get("status")),
        "country": _first(record.get("country")),
    }


def get_whois(target, target_type):
    source = "WHOIS"
    if target_type == "IP Address":
        return {"source": source, "status": "unsupported", "data": {}, "error": "WHOIS lookup is not applicable to this target type."}
    if target_type == "Domain":
        domain = target
    elif target_type == "URL":
        domain = _extract_domain_from_url(target)
        if not domain:
            return {"source": source, "status": "error", "data": {}, "error": "Could not extract a domain from the URL."}
    else:
        return {"source": source, "status": "unsupported", "data": {}, "error": f"WHOIS does not support target type '{target_type}'."}
    try:
        data = _whois_lookup(domain)
        if not data.get("registrar") and not data.get("created"):
            return {"source": source, "status": "success", "data": {"note": f"No meaningful WHOIS record found for '{domain}'."}, "error": None}
        return {"source": source, "status": "success", "data": data, "error": None}
    except Exception as exc:
        return {"source": source, "status": "error", "data": {}, "error": f"WHOIS lookup failed: {exc}"}


SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}