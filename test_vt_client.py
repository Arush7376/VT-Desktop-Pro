import unittest
import vt_client


class TestVTClient(unittest.TestCase):

    def setUp(self):
        self.client = vt_client.VTClient(api_key="test_api_key_12345")

    def test_normalization_file_response(self):
        mock_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 45,
                        "suspicious": 3,
                        "harmless": 10,
                        "undetected": 12
                    },
                    "type_description": "Executable",
                    "size": 1048576,
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    "reputation": -50,
                    "tags": ["executable", "signed"],
                    "categories": {"VendorA": "malware", "VendorB": "trojan"},
                    "first_submission_date": 1600000000,
                    "last_analysis_date": 1610000000,
                    "last_analysis_results": {
                        "Avast": {"category": "malicious", "result": "Win32:Malware-gen"}
                    }
                }
            }
        }

        ioc_info = {
            "value": "sample.exe",
            "type": "FILE",
            "is_file": True
        }

        res = self.client._normalize_response(mock_data, ioc_info)

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["ioc"], "sample.exe")
        self.assertEqual(res["ioc_type"], "FILE")
        self.assertEqual(res["malicious_count"], 45)
        self.assertEqual(res["suspicious_count"], 3)
        self.assertEqual(res["detection_count"], 48)
        self.assertEqual(res["total_engines"], 70)
        self.assertEqual(res["harmless_count"], 10)
        self.assertEqual(res["undetected_count"], 12)
        self.assertEqual(res["reputation"], -50)
        self.assertIn("executable", res["tags"])
        self.assertEqual(res["categories"], ["malware", "trojan"])
        self.assertEqual(res["first_submission_date"], "2020-09-13 12:26:40 UTC")
        self.assertEqual(res["last_analysis_date"], "2021-01-07 16:53:20 UTC")
        self.assertEqual(res["sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_timestamp_formatting(self):
        ts_str = self.client._format_timestamp(1600000000)
        self.assertEqual(ts_str, "2020-09-13 12:26:40 UTC")

        none_str = self.client._format_timestamp(None)
        self.assertEqual(none_str, "N/A")

        invalid_str = self.client._format_timestamp("invalid")
        self.assertEqual(invalid_str, "N/A")

    def test_missing_api_key_handling(self):
        client_no_key = vt_client.VTClient(api_key="")
        res = client_no_key.fetch_ioc_report({"value": "8.8.8.8", "type": "IPV4", "vt_endpoint": "ip_addresses/8.8.8.8"})
        self.assertEqual(res["status"], "invalid_api_key")
        self.assertIn("missing", res["error_message"])

    def test_missing_endpoint_handling(self):
        res = self.client.fetch_ioc_report({"value": "invalid", "type": "UNKNOWN", "vt_endpoint": None, "error": "Invalid format"})
        self.assertEqual(res["status"], "error")
        self.assertIn("Invalid format", res["error_message"])


if __name__ == "__main__":
    unittest.main()
