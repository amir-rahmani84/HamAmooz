import unittest
from parser import parse_line, parse_timestamp
from datetime import datetime, timezone


# the commented Tests Bellow should be used if we dont trust the source and instead use the other Regex
class TestParser(unittest.TestCase):

    # ---------- valid line parsing ----------
    def test_valid_get_line(self):
        line = '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET /products/1877 HTTP/1.1" 200 5324 "-" "Mozilla/5.0"'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, '203.0.113.42')
        self.assertEqual(entry.method, 'GET')
        self.assertEqual(entry.path, '/products/1877')
        self.assertEqual(entry.protocol, 'HTTP/1.1')
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.size, 5324)
        self.assertEqual(entry.user_agent, 'Mozilla/5.0')
        self.assertEqual(entry.timestamp, datetime(2026, 6, 1, 9, 14, 22, tzinfo=timezone.utc))

    # Referer is ignored in our model, so we don't test it, but the line should parse.
    def test_valid_line_with_referer(self):
        line = '10.0.0.1 - - [02/Jan/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 304 0 "https://example.com" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.path, '/index.html')
        self.assertEqual(entry.status, 304)

    def test_valid_line_with_empty_user_agent(self):
        line = '10.0.0.2 - - [02/Jan/2026:12:00:01 +0000] "GET /favicon.ico HTTP/1.1" 404 0 "-" ""'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.user_agent, '')

    def test_valid_line_with_size_dash(self):
        line = '10.0.0.3 - - [02/Jan/2026:12:00:02 +0000] "HEAD /largefile HTTP/1.1" 200 - "-" "bot"'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.size, 0)   # "-" becomes 0

    def test_valid_line_http2(self):
        line = '2001:db8::1 - - [02/Jan/2026:12:00:03 +0000] "GET /api HTTP/2.0" 200 123 "-" "curl"'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.protocol, 'HTTP/2.0')

    # ---------- timestamp parsing ----------
    def test_parse_timestamp_valid(self):
        dt = parse_timestamp("01/Jun/2026:09:14:22 +0000")
        expected = datetime(2026, 6, 1, 9, 14, 22, tzinfo=timezone.utc)
        self.assertEqual(dt, expected)

    def test_parse_timestamp_invalid_format(self):
        with self.assertRaises(ValueError):
            parse_timestamp("2026-06-01 09:14:22")   # wrong format

    # ---------- malformed lines ----------
    def test_malformed_line_garbage(self):
        line = 'garbage data'
        self.assertIsNone(parse_line(line))

    def test_malformed_line_missing_fields(self):
        line = '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET /products/1877 HTTP/1.1" 200'
        self.assertIsNone(parse_line(line))

    # def test_malformed_line_wrong_status(self):
    #     line = '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET /products/1877 HTTP/1.1" 999 5324 "-" "Mozilla"'
    #     self.assertIsNone(parse_line(line))  # status 999 not valid in our regex (TRUST_PATTERN accepts any 3 digits though)

    # def test_malformed_line_wrong_ip(self):
    #     line = '999.999.999.999 - - [01/Jun/2026:09:14:22 +0000] "GET / HTTP/1.1" 200 0 "-" "-"'
    #     self.assertIsNone(parse_line(line))  # Depending on LOG_PATTERN, if it's TRUST_LOG_PATTERN, it accepts any non-space as IP, so it would parse. But we have FULL_LOG_PATTERN commented. Our code uses TRUST_LOG_PATTERN, which accepts any \S+ as IP, so this would actually parse. That's a design choice. We'll keep it as is.

    # def test_malformed_line_wrong_method(self):
    #     line = '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "INVALID / HTTP/1.1" 200 0 "-" "-"'
    #     self.assertIsNone(parse_line(line))

    def test_malformed_line_empty_path(self):
        line = '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET  HTTP/1.1" 200 0 "-" "-"'
        self.assertIsNone(parse_line(line))

    def test_malformed_line_missing_quote(self):
        line = '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET / HTTP/1.1 200 0 "-" "-"'
        self.assertIsNone(parse_line(line))

    def test_malformed_line_extra_spaces(self):
        # Some log lines may have extra spaces; our regex might fail.
        line = '  203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET / HTTP/1.1" 200 0 "-" "-"'
        self.assertIsNone(parse_line(line))

if __name__ == '__main__':
    unittest.main()