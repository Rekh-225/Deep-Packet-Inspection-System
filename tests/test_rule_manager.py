"""
Unit tests for dpi.rule_manager module.

Tests blocking rules: IP, Application, Domain (with wildcards), and Port.
"""

import os
import tempfile
import unittest

from dpi.types import AppType, str_to_ip
from dpi.rule_manager import RuleManager


class TestIPBlocking(unittest.TestCase):

    def setUp(self):
        self.rm = RuleManager()

    def test_block_and_check_ip(self):
        self.rm.block_ip("192.168.1.100")
        ip = str_to_ip("192.168.1.100")
        self.assertTrue(self.rm.is_ip_blocked(ip))

    def test_unblocked_ip(self):
        ip = str_to_ip("10.0.0.1")
        self.assertFalse(self.rm.is_ip_blocked(ip))

    def test_unblock_ip(self):
        self.rm.block_ip("192.168.1.100")
        self.rm.unblock_ip("192.168.1.100")
        ip = str_to_ip("192.168.1.100")
        self.assertFalse(self.rm.is_ip_blocked(ip))


class TestAppBlocking(unittest.TestCase):

    def setUp(self):
        self.rm = RuleManager()

    def test_block_app_by_enum(self):
        self.rm.block_app(AppType.YOUTUBE)
        self.assertTrue(self.rm.is_app_blocked(AppType.YOUTUBE))
        self.assertFalse(self.rm.is_app_blocked(AppType.FACEBOOK))

    def test_block_app_by_name(self):
        self.rm.block_app("YouTube")
        self.assertTrue(self.rm.is_app_blocked(AppType.YOUTUBE))

    def test_block_app_case_insensitive(self):
        self.rm.block_app("youtube")
        self.assertTrue(self.rm.is_app_blocked(AppType.YOUTUBE))

    def test_unblock_app(self):
        self.rm.block_app("YouTube")
        self.rm.unblock_app("YouTube")
        self.assertFalse(self.rm.is_app_blocked(AppType.YOUTUBE))


class TestDomainBlocking(unittest.TestCase):

    def setUp(self):
        self.rm = RuleManager()

    def test_block_exact_domain(self):
        self.rm.block_domain("malware.com")
        self.assertTrue(self.rm.is_domain_blocked("malware.com"))

    def test_substring_match(self):
        self.rm.block_domain("tiktok")
        self.assertTrue(self.rm.is_domain_blocked("www.tiktok.com"))
        self.assertTrue(self.rm.is_domain_blocked("api.tiktok.com"))

    def test_wildcard_domain(self):
        self.rm.block_domain("*.facebook.com")
        self.assertTrue(self.rm.is_domain_blocked("www.facebook.com"))
        self.assertTrue(self.rm.is_domain_blocked("api.facebook.com"))
        self.assertTrue(self.rm.is_domain_blocked("facebook.com"))

    def test_unrelated_domain_not_blocked(self):
        self.rm.block_domain("malware.com")
        self.assertFalse(self.rm.is_domain_blocked("google.com"))

    def test_unblock_domain(self):
        self.rm.block_domain("malware.com")
        self.rm.unblock_domain("malware.com")
        self.assertFalse(self.rm.is_domain_blocked("malware.com"))


class TestPortBlocking(unittest.TestCase):

    def setUp(self):
        self.rm = RuleManager()

    def test_block_port(self):
        self.rm.block_port(8080)
        self.assertTrue(self.rm.is_port_blocked(8080))
        self.assertFalse(self.rm.is_port_blocked(443))

    def test_unblock_port(self):
        self.rm.block_port(8080)
        self.rm.unblock_port(8080)
        self.assertFalse(self.rm.is_port_blocked(8080))


class TestCombinedShouldBlock(unittest.TestCase):

    def setUp(self):
        self.rm = RuleManager()

    def test_block_by_ip(self):
        self.rm.block_ip("192.168.1.50")
        result = self.rm.should_block(
            str_to_ip("192.168.1.50"), 443, AppType.UNKNOWN, ""
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.type, "ip")

    def test_block_by_app(self):
        self.rm.block_app("YouTube")
        result = self.rm.should_block(
            str_to_ip("10.0.0.1"), 443, AppType.YOUTUBE, "www.youtube.com"
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.type, "app")

    def test_block_by_domain(self):
        self.rm.block_domain("tiktok")
        result = self.rm.should_block(
            str_to_ip("10.0.0.1"), 443, AppType.TIKTOK, "www.tiktok.com"
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.type, "domain")

    def test_not_blocked(self):
        result = self.rm.should_block(
            str_to_ip("10.0.0.1"), 443, AppType.GOOGLE, "www.google.com"
        )
        self.assertIsNone(result)


class TestRulePersistence(unittest.TestCase):

    def test_save_and_load(self):
        rm1 = RuleManager()
        rm1.block_ip("192.168.1.100")
        rm1.block_app("YouTube")
        rm1.block_domain("malware.com")
        rm1.block_port(8080)

        tmp = tempfile.NamedTemporaryFile(suffix=".rules", delete=False, mode="w")
        tmp.close()

        try:
            rm1.save_rules(tmp.name)

            rm2 = RuleManager()
            rm2.load_rules(tmp.name)

            self.assertTrue(rm2.is_ip_blocked(str_to_ip("192.168.1.100")))
            self.assertTrue(rm2.is_app_blocked(AppType.YOUTUBE))
            self.assertTrue(rm2.is_domain_blocked("malware.com"))
            self.assertTrue(rm2.is_port_blocked(8080))
        finally:
            os.unlink(tmp.name)


class TestStats(unittest.TestCase):

    def test_get_stats(self):
        rm = RuleManager()
        rm.block_ip("1.2.3.4")
        rm.block_app("YouTube")
        rm.block_domain("test.com")
        rm.block_port(80)

        stats = rm.get_stats()
        self.assertEqual(stats["blocked_ips"], 1)
        self.assertEqual(stats["blocked_apps"], 1)
        self.assertEqual(stats["blocked_domains"], 1)
        self.assertEqual(stats["blocked_ports"], 1)

    def test_clear_all(self):
        rm = RuleManager()
        rm.block_ip("1.2.3.4")
        rm.block_app("YouTube")
        rm.clear_all()

        stats = rm.get_stats()
        self.assertEqual(stats["blocked_ips"], 0)
        self.assertEqual(stats["blocked_apps"], 0)


if __name__ == "__main__":
    unittest.main()
