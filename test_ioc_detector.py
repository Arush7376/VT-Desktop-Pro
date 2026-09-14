import os
import unittest
import tempfile
import ioc_detector


class TestIOCDetector(unittest.TestCase):

    def test_sha256_hash(self):
        sha256_input = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        res = ioc_detector.detect_ioc(sha256_input)
        self.assertEqual(res["type"], "SHA256")
        self.assertTrue(res["valid"])
        self.assertEqual(res["vt_endpoint"], f"files/{sha256_input}")
        self.assertFalse(res["is_file"])

    def test_md5_hash(self):
        md5_input = "d41d8cd98f00b204e9800998ecf8427e"
        res = ioc_detector.detect_ioc(md5_input)
        self.assertEqual(res["type"], "MD5")
        self.assertTrue(res["valid"])
        self.assertEqual(res["vt_endpoint"], f"files/{md5_input}")

    def test_sha1_hash(self):
        sha1_input = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        res = ioc_detector.detect_ioc(sha1_input)
        self.assertEqual(res["type"], "SHA1")
        self.assertTrue(res["valid"])
        self.assertEqual(res["vt_endpoint"], f"files/{sha1_input}")

    def test_ipv4_address(self):
        ip_input = "8.8.8.8"
        res = ioc_detector.detect_ioc(ip_input)
        self.assertEqual(res["type"], "IPV4")
        self.assertTrue(res["valid"])
        self.assertEqual(res["vt_endpoint"], "ip_addresses/8.8.8.8")

    def test_ipv6_address(self):
        ipv6_input = "2001:4860:4860::8888"
        res = ioc_detector.detect_ioc(ipv6_input)
        self.assertEqual(res["type"], "IPV6")
        self.assertTrue(res["valid"])
        self.assertEqual(res["vt_endpoint"], "ip_addresses/2001:4860:4860::8888")

    def test_domain(self):
        domain_input = "example.com"
        res = ioc_detector.detect_ioc(domain_input)
        self.assertEqual(res["type"], "DOMAIN")
        self.assertTrue(res["valid"])
        self.assertEqual(res["vt_endpoint"], "domains/example.com")

    def test_url(self):
        url_input = "https://example.com/malware_test?id=123"
        res = ioc_detector.detect_ioc(url_input)
        self.assertEqual(res["type"], "URL")
        self.assertTrue(res["valid"])
        self.assertTrue(res["vt_endpoint"].startswith("urls/"))

    def test_local_file(self):
        # Create temp file with known content
        content = b"VT Desktop Pro IOC Unit Test Sample File"
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        try:
            res = ioc_detector.detect_ioc(tmp_path)
            self.assertEqual(res["type"], "FILE")
            self.assertTrue(res["valid"])
            self.assertTrue(res["is_file"])
            self.assertIsNotNone(res["hashes"])
            self.assertIn("sha256", res["hashes"])
            self.assertIn("sha1", res["hashes"])
            self.assertIn("md5", res["hashes"])
            self.assertTrue(res["vt_endpoint"].startswith("files/"))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_edge_cases(self):
        # Empty string
        res_empty = ioc_detector.detect_ioc("")
        self.assertEqual(res_empty["type"], "UNKNOWN")
        self.assertFalse(res_empty["valid"])

        # Invalid string
        res_invalid = ioc_detector.detect_ioc("not_an_ioc_###!!!")
        self.assertEqual(res_invalid["type"], "UNKNOWN")
        self.assertFalse(res_invalid["valid"])

        # Directory path
        res_dir = ioc_detector.detect_ioc(os.path.dirname(os.path.abspath(__file__)))
        self.assertEqual(res_dir["type"], "FILE")
        self.assertFalse(res_dir["valid"])
        self.assertIn("directory", res_dir["error"])


if __name__ == "__main__":
    unittest.main()
