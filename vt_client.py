import os
import requests
import datetime
from typing import Dict, Any, Optional


class VTClient:
    """
    Dedicated VirusTotal API v3 Client and Intelligence Service.
    Handles network requests, timeouts, HTTP status errors, and normalizes VT payloads into a consistent data model.
    """

    def __init__(self, api_key: str, base_url: str = "https://www.virustotal.com/api/v3", timeout: int = 15):
        self.api_key = api_key.strip() if api_key else ""
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.headers = {"x-apikey": self.api_key}

    def _scrub_api_key(self, text: str) -> str:
        """Redact API key from any string representation if present."""
        if not text or not self.api_key:
            return str(text) if text is not None else ""
        return str(text).replace(self.api_key, "***")

    def fetch_ioc_report(self, ioc_info: dict) -> dict:
        """
        Fetch threat intelligence for an IOC dictionary produced by ioc_detector.
        """
        if not self.api_key:
            return {
                "status": "invalid_api_key",
                "error_message": "VirusTotal API key is missing.",
                "ioc": ioc_info.get("value", ""),
                "ioc_type": ioc_info.get("type", "UNKNOWN")
            }

        endpoint = ioc_info.get("vt_endpoint")
        if not endpoint:
            return {
                "status": "error",
                "error_message": ioc_info.get("error", "Invalid or missing endpoint for target."),
                "ioc": ioc_info.get("value", ""),
                "ioc_type": ioc_info.get("type", "UNKNOWN")
            }

        url = f"{self.base_url}/{endpoint}"

        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()
                return self._normalize_response(data, ioc_info)

            elif response.status_code == 404:
                return {
                    "status": "not_found",
                    "error_message": "Target not found in VirusTotal database.",
                    "ioc": ioc_info.get("value", ""),
                    "ioc_type": ioc_info.get("type", "UNKNOWN"),
                    "is_file": ioc_info.get("is_file", False)
                }

            elif response.status_code in (401, 403):
                return {
                    "status": "invalid_api_key",
                    "error_message": f"Invalid or unauthorized VirusTotal API key (HTTP {response.status_code}).",
                    "ioc": ioc_info.get("value", ""),
                    "ioc_type": ioc_info.get("type", "UNKNOWN")
                }

            elif response.status_code == 429:
                return {
                    "status": "rate_limit_exceeded",
                    "error_message": "VirusTotal API rate limit or quota exceeded (HTTP 429).",
                    "ioc": ioc_info.get("value", ""),
                    "ioc_type": ioc_info.get("type", "UNKNOWN")
                }

            else:
                return {
                    "status": "error",
                    "error_message": f"VirusTotal API returned HTTP {response.status_code}.",
                    "ioc": ioc_info.get("value", ""),
                    "ioc_type": ioc_info.get("type", "UNKNOWN")
                }

        except requests.Timeout:
            return {
                "status": "error",
                "error_message": f"Network request timed out ({self.timeout}s). Please check your connection.",
                "ioc": ioc_info.get("value", ""),
                "ioc_type": ioc_info.get("type", "UNKNOWN")
            }

        except requests.ConnectionError:
            return {
                "status": "error",
                "error_message": "Network connection error. Failed to reach VirusTotal servers.",
                "ioc": ioc_info.get("value", ""),
                "ioc_type": ioc_info.get("type", "UNKNOWN")
            }

        except requests.RequestException as e:
            err_msg = self._scrub_api_key(str(e))
            return {
                "status": "error",
                "error_message": f"HTTP error occurred: {err_msg}",
                "ioc": ioc_info.get("value", ""),
                "ioc_type": ioc_info.get("type", "UNKNOWN")
            }

    def upload_file(self, filepath: str, upload_timeout: int = 60) -> dict:
        """
        Upload a file to VirusTotal API v3 /files endpoint.
        """
        if not self.api_key:
            return {"success": False, "message": "API key missing."}

        clean_path = filepath.strip('"\'')
        if not os.path.exists(clean_path) or not os.path.isfile(clean_path):
            return {"success": False, "message": "File does not exist or is not a valid file."}

        url = f"{self.base_url}/files"

        try:
            with open(clean_path, "rb") as f:
                files = {"file": f}
                res = requests.post(url, headers=self.headers, files=files, timeout=upload_timeout)

            if res.status_code == 200:
                data = res.json()
                analysis_id = data.get("data", {}).get("id", "")
                return {
                    "success": True,
                    "analysis_id": analysis_id,
                    "message": "File successfully uploaded to VirusTotal."
                }
            elif res.status_code in (401, 403):
                return {"success": False, "message": "Invalid or unauthorized VirusTotal API key."}
            elif res.status_code == 429:
                return {"success": False, "message": "API rate limit exceeded."}
            else:
                return {"success": False, "message": f"Upload failed with HTTP {res.status_code}."}

        except requests.Timeout:
            return {"success": False, "message": f"Upload timed out ({upload_timeout}s)."}
        except requests.RequestException as e:
            err_msg = str(e).replace(self.api_key, "***") if self.api_key else str(e)
            return {"success": False, "message": f"Upload network error: {err_msg}"}

    def _normalize_response(self, data: dict, ioc_info: dict) -> dict:
        """
        Normalize VirusTotal API v3 response into standard internal intelligence payload format.
        """
        attr = data.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        timeout_cnt = stats.get("timeout", 0)
        confirmed_timeout = stats.get("confirmed-timeout", 0)
        type_unsupported = stats.get("type-unsupported", 0)

        detection_count = malicious + suspicious
        total_engines = sum(stats.values())

        first_sub_ts = attr.get("first_submission_date")
        first_sub_str = self._format_timestamp(first_sub_ts)

        last_analysis_ts = attr.get("last_analysis_date")
        last_analysis_str = self._format_timestamp(last_analysis_ts)

        local_hashes = ioc_info.get("hashes") or {}
        sha256 = attr.get("sha256") or local_hashes.get("sha256", "N/A")
        md5 = attr.get("md5") or local_hashes.get("md5", "N/A")
        sha1 = attr.get("sha1") or local_hashes.get("sha1", "N/A")

        raw_cats = attr.get("categories", {})
        categories = []
        if isinstance(raw_cats, dict):
            categories = sorted(list(set(raw_cats.values())))
        elif isinstance(raw_cats, list):
            categories = raw_cats

        return {
            "status": "success",
            "error_message": None,
            "ioc": ioc_info.get("value", ""),
            "ioc_type": ioc_info.get("type", "UNKNOWN"),
            "detection_count": detection_count,
            "total_engines": total_engines,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "undetected_count": undetected,
            "timeout_count": timeout_cnt + confirmed_timeout,
            "unsupported_count": type_unsupported,
            "reputation": attr.get("reputation", 0),
            "type_description": attr.get("type_description", attr.get("meaningful_name", "N/A")),
            "size": attr.get("size", "N/A"),
            "tags": attr.get("tags", []),
            "categories": categories,
            "first_submission_date": first_sub_str,
            "last_analysis_date": last_analysis_str,
            "sha256": sha256,
            "md5": md5,
            "sha1": sha1,
            "engines": attr.get("last_analysis_results", {}),
            "raw_json": data
        }

    @staticmethod
    def _format_timestamp(ts: Optional[int]) -> str:
        if not ts or not isinstance(ts, (int, float)):
            return "N/A"
        try:
            dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return "N/A"
