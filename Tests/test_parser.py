import unittest
from datetime import datetime
from parser import parse_line, parse_timestamp, TRUST_PATTERN, STRICT_PATTERN
from models import LogEntry

class TestParser(unittest.TestCase):
    def test_parse_timestamp(self):
        ts = "01/Jun/2026:09:14:22 +0000"
        dt = parse_timestamp(ts)
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 6)
        self.assertEqual(dt.day, 1)
        self.assertEqual(dt.hour, 9)
        self.assertEqual(dt.minute, 14)
        self.assertEqual(dt.second, 22)
        self.assertEqual(dt.tzinfo is not None, True)

    def test_parse_line_trust_valid(self):
        line = ('192.168.1.1 - - [01/Jun/2026:09:14:22 +0000] '
                '"GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"')
        entry = parse_line(line, strict=False)
        self.assertIsInstance(entry, LogEntry)
        self.assertEqual(entry.ip, "192.168.1.1")
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.path, "/index.html")
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.size, 1234)
        self.assertEqual(entry.user_agent, "Mozilla/5.0")

    def test_parse_line_trust_malformed(self):
        line = "garbage line"
        entry = parse_line(line, strict=False)
        self.assertIsNone(entry)

    def test_parse_line_strict_valid_ipv4(self):
        line = ('192.168.1.1 - - [01/Jun/2026:09:14:22 +0000] '
                '"GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"')
        entry = parse_line(line, strict=True)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "192.168.1.1")

    def test_parse_line_strict_valid_ipv6(self):
        line = ('2001:0db8:85a3:0000:0000:8a2e:0370:7334 - - [01/Jun/2026:09:14:22 +0000] '
                '"GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"')
        entry = parse_line(line, strict=True)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "2001:0db8:85a3:0000:0000:8a2e:0370:7334")

    def test_parse_line_strict_invalid_status(self):
        line = ('192.168.1.1 - - [01/Jun/2026:09:14:22 +0000] '
                '"GET /index.html HTTP/1.1" 999 1234 "-" "Mozilla/5.0"')
        entry = parse_line(line, strict=True)
        self.assertIsNone(entry)

if __name__ == '__main__':
    unittest.main()