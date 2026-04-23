"""
Unit tests for dpi.types module.

Tests enums, FiveTuple operations, and SNI-to-app classification.
"""

import unittest
from dpi.types import (
    AppType,
    ConnectionState,
    PacketAction,
    FiveTuple,
    Connection,
    DPIStats,
    ip_to_str,
    str_to_ip,
    sni_to_app_type,
    app_name_to_type,
)


class TestAppType(unittest.TestCase):
    """Test AppType enum."""

    def test_all_apps_have_display_names(self):
        for app in AppType:
            self.assertIsInstance(app.value, str)
            self.assertTrue(len(app.value) > 0)

    def test_specific_values(self):
        self.assertEqual(AppType.YOUTUBE.value, "YouTube")
        self.assertEqual(AppType.FACEBOOK.value, "Facebook")
        self.assertEqual(AppType.UNKNOWN.value, "Unknown")

    def test_app_name_to_type(self):
        self.assertEqual(app_name_to_type("YouTube"), AppType.YOUTUBE)
        self.assertEqual(app_name_to_type("youtube"), AppType.YOUTUBE)
        self.assertEqual(app_name_to_type("YOUTUBE"), AppType.YOUTUBE)
        self.assertIsNone(app_name_to_type("NonExistentApp"))


class TestFiveTuple(unittest.TestCase):
    """Test FiveTuple dataclass."""

    def setUp(self):
        self.tuple = FiveTuple(
            src_ip=0x0100A8C0,   # 192.168.0.1 in LE
            dst_ip=0x0101A8C0,   # 192.168.1.1 in LE
            src_port=12345,
            dst_port=443,
            protocol=6,
        )

    def test_frozen(self):
        with self.assertRaises(AttributeError):
            self.tuple.src_port = 999

    def test_hash(self):
        same = FiveTuple(0x0100A8C0, 0x0101A8C0, 12345, 443, 6)
        self.assertEqual(hash(self.tuple), hash(same))

    def test_equality(self):
        same = FiveTuple(0x0100A8C0, 0x0101A8C0, 12345, 443, 6)
        self.assertEqual(self.tuple, same)

    def test_reverse(self):
        rev = self.tuple.reverse()
        self.assertEqual(rev.src_ip, self.tuple.dst_ip)
        self.assertEqual(rev.dst_ip, self.tuple.src_ip)
        self.assertEqual(rev.src_port, self.tuple.dst_port)
        self.assertEqual(rev.dst_port, self.tuple.src_port)
        self.assertEqual(rev.protocol, self.tuple.protocol)

    def test_reverse_of_reverse(self):
        self.assertEqual(self.tuple.reverse().reverse(), self.tuple)

    def test_usable_as_dict_key(self):
        d = {self.tuple: "flow1"}
        same = FiveTuple(0x0100A8C0, 0x0101A8C0, 12345, 443, 6)
        self.assertEqual(d[same], "flow1")


class TestIPConversions(unittest.TestCase):
    """Test IP address string <-> int conversions."""

    def test_ip_to_str(self):
        ip = str_to_ip("192.168.1.100")
        self.assertEqual(ip_to_str(ip), "192.168.1.100")

    def test_str_to_ip_roundtrip(self):
        for addr in ("0.0.0.0", "255.255.255.255", "10.0.0.1", "192.168.1.100"):
            self.assertEqual(ip_to_str(str_to_ip(addr)), addr)

    def test_loopback(self):
        ip = str_to_ip("127.0.0.1")
        self.assertEqual(ip_to_str(ip), "127.0.0.1")


class TestSNIClassification(unittest.TestCase):
    """Test SNI to AppType mapping."""

    def test_youtube(self):
        self.assertEqual(sni_to_app_type("www.youtube.com"), AppType.YOUTUBE)
        self.assertEqual(sni_to_app_type("i.ytimg.com"), AppType.YOUTUBE)
        self.assertEqual(sni_to_app_type("youtu.be"), AppType.YOUTUBE)

    def test_google(self):
        self.assertEqual(sni_to_app_type("www.google.com"), AppType.GOOGLE)
        self.assertEqual(sni_to_app_type("fonts.googleapis.com"), AppType.GOOGLE)

    def test_facebook(self):
        self.assertEqual(sni_to_app_type("www.facebook.com"), AppType.FACEBOOK)
        self.assertEqual(sni_to_app_type("static.fbcdn.net"), AppType.FACEBOOK)

    def test_instagram(self):
        self.assertEqual(sni_to_app_type("www.instagram.com"), AppType.INSTAGRAM)

    def test_netflix(self):
        self.assertEqual(sni_to_app_type("www.netflix.com"), AppType.NETFLIX)
        self.assertEqual(sni_to_app_type("stream.nflxvideo.net"), AppType.NETFLIX)

    def test_twitter(self):
        self.assertEqual(sni_to_app_type("twitter.com"), AppType.TWITTER)
        self.assertEqual(sni_to_app_type("pbs.twimg.com"), AppType.TWITTER)
        self.assertEqual(sni_to_app_type("x.com"), AppType.TWITTER)
        self.assertEqual(sni_to_app_type("t.co"), AppType.TWITTER)

    def test_twitter_does_not_match_others(self):
        """t.co must NOT match netflix, microsoft, etc."""
        self.assertNotEqual(sni_to_app_type("www.netflix.com"), AppType.TWITTER)
        self.assertNotEqual(sni_to_app_type("www.microsoft.com"), AppType.TWITTER)

    def test_microsoft(self):
        self.assertEqual(sni_to_app_type("www.microsoft.com"), AppType.MICROSOFT)
        self.assertEqual(sni_to_app_type("login.live.com"), AppType.MICROSOFT)

    def test_amazon(self):
        self.assertEqual(sni_to_app_type("www.amazon.com"), AppType.AMAZON)
        self.assertEqual(sni_to_app_type("d1.cloudfront.net"), AppType.AMAZON)

    def test_tiktok(self):
        self.assertEqual(sni_to_app_type("www.tiktok.com"), AppType.TIKTOK)
        self.assertEqual(sni_to_app_type("api.bytedance.com"), AppType.TIKTOK)

    def test_discord(self):
        self.assertEqual(sni_to_app_type("discord.com"), AppType.DISCORD)

    def test_spotify(self):
        self.assertEqual(sni_to_app_type("open.spotify.com"), AppType.SPOTIFY)

    def test_zoom(self):
        self.assertEqual(sni_to_app_type("zoom.us"), AppType.ZOOM)

    def test_github(self):
        self.assertEqual(sni_to_app_type("github.com"), AppType.GITHUB)

    def test_unknown_sni(self):
        self.assertEqual(sni_to_app_type("totallyunknown.example.org"), AppType.HTTPS)

    def test_empty_sni(self):
        self.assertEqual(sni_to_app_type(""), AppType.UNKNOWN)
        self.assertEqual(sni_to_app_type(None), AppType.UNKNOWN)

    def test_case_insensitive(self):
        self.assertEqual(sni_to_app_type("WWW.YOUTUBE.COM"), AppType.YOUTUBE)
        self.assertEqual(sni_to_app_type("Www.Google.Com"), AppType.GOOGLE)


class TestConnection(unittest.TestCase):
    """Test Connection dataclass defaults."""

    def test_defaults(self):
        t = FiveTuple(0, 0, 0, 0, 6)
        conn = Connection(tuple=t)
        self.assertEqual(conn.state, ConnectionState.NEW)
        self.assertEqual(conn.app_type, AppType.UNKNOWN)
        self.assertEqual(conn.packets_in, 0)
        self.assertEqual(conn.action, PacketAction.FORWARD)


if __name__ == "__main__":
    unittest.main()
