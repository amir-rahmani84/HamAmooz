import unittest
from processor import process_file
import tempfile
import os

class TestProcessor(unittest.TestCase):

    def setUp(self):
        self.temp_files = []

    def tearDown(self):
        for fname in self.temp_files:
            if os.path.exists(fname):
                os.unlink(fname)

    def _create_temp_file(self, content):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as f:
            f.write(content)
            fname = f.name
            self.temp_files.append(fname)
            return fname

    def test_process_file_mixed_valid_malformed(self):
        content = (
            '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET /a HTTP/1.1" 200 100 "-" "-"\n'
            '192.168.1.1 - - [01/Jun/2026:09:15:00 +0000] "POST /b HTTP/1.1" 404 200 "-" "-"\n'
            '192.168.1.1 - - [01/Jun/2026:09:15:47 +0000] "GET /a HTTP/1.1" 200 100 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"\n'
            'malformed line\n'
        )
        fname = self._create_temp_file(content)
        stats = process_file(fname)
        self.assertEqual(stats['total_requests'], 3)
        self.assertEqual(stats['bad_lines'], 1)
        self.assertEqual(stats['unique_ips'], 2)   # 203.0.113.42 and 192.168.1.1
        self.assertEqual(stats['top_endpoints'][0][0], '/a')  # most common
        self.assertEqual(stats['top_endpoints'][0][1], 2)     # /a appears twice
        self.assertEqual(stats['error_requests'], 1)          # 404 is error
        self.assertAlmostEqual(stats['error_rate'], 33.33333333333333)  # 1/3

    def test_process_file_empty_file(self):
        fname = self._create_temp_file('')
        stats = process_file(fname)
        self.assertEqual(stats['total_requests'], 0)
        self.assertEqual(stats['bad_lines'], 0)
        self.assertEqual(stats['unique_ips'], 0)
        self.assertEqual(stats['top_endpoints'], [])
        self.assertEqual(stats['error_requests'], 0)
        self.assertEqual(stats['error_rate'], 0.0)
        self.assertEqual(stats['hourly_distribution'], {})

    def test_process_file_all_malformed(self):
        content = 'garbage1\ngarbage2\n'
        fname = self._create_temp_file(content)
        stats = process_file(fname)
        self.assertEqual(stats['total_requests'], 0)
        self.assertEqual(stats['bad_lines'], 2)
        self.assertEqual(stats['unique_ips'], 0)
        self.assertEqual(stats['error_rate'], 0.0)

    def test_process_file_only_valid(self):
        content = (
            '1.1.1.1 - - [01/Jun/2026:09:00:00 +0000] "GET /x HTTP/1.1" 200 10 "-" "-"\n'
            '2.2.2.2 - - [01/Jun/2026:10:00:00 +0000] "GET /y HTTP/1.1" 500 20 "-" "-"\n'
        )
        fname = self._create_temp_file(content)
        stats = process_file(fname)
        self.assertEqual(stats['total_requests'], 2)
        self.assertEqual(stats['bad_lines'], 0)
        self.assertEqual(stats['unique_ips'], 2)
        self.assertEqual(stats['top_endpoints'], [('/x', 1), ('/y', 1)])
        self.assertEqual(stats['error_requests'], 1)
        self.assertEqual(stats['error_rate'], 50.0)
        self.assertEqual(stats['hourly_distribution'][9], 1)
        self.assertEqual(stats['hourly_distribution'][10], 1)

    def test_process_file_hourly_distribution(self):
        content = (
            '1.1.1.1 - - [01/Jun/2026:00:05:00 +0000] "GET /a HTTP/1.1" 200 1 "-" "-"\n'
            '1.1.1.1 - - [01/Jun/2026:00:10:00 +0000] "GET /b HTTP/1.1" 200 1 "-" "-"\n'
            '2.2.2.2 - - [01/Jun/2026:23:59:59 +0000] "GET /c HTTP/1.1" 200 1 "-" "-"\n'
        )
        fname = self._create_temp_file(content)
        stats = process_file(fname)
        self.assertEqual(stats['hourly_distribution'][0], 2)
        self.assertEqual(stats['hourly_distribution'][23], 1)
        self.assertEqual(len(stats['hourly_distribution']), 2)

    def test_process_file_duplicate_ips_count_once(self):
        content = (
            '1.1.1.1 - - [01/Jun/2026:00:00:00 +0000] "GET /a HTTP/1.1" 200 1 "-" "-"\n'
            '1.1.1.1 - - [01/Jun/2026:00:00:01 +0000] "GET /b HTTP/1.1" 200 1 "-" "-"\n'
            '2.2.2.2 - - [01/Jun/2026:00:00:02 +0000] "GET /c HTTP/1.1" 200 1 "-" "-"\n'
        )
        fname = self._create_temp_file(content)
        stats = process_file(fname)
        self.assertEqual(stats['unique_ips'], 2)

    def test_process_file_top_endpoints_ordering(self):
        content = (
            '1.1.1.1 - - [01/Jun/2026:00:00:00 +0000] "GET /a HTTP/1.1" 200 1 "-" "-"\n'
            '2.2.2.2 - - [01/Jun/2026:00:00:01 +0000] "GET /b HTTP/1.1" 200 1 "-" "-"\n'
            '3.3.3.3 - - [01/Jun/2026:00:00:02 +0000] "GET /a HTTP/1.1" 200 1 "-" "-"\n'
            '4.4.4.4 - - [01/Jun/2026:00:00:03 +0000] "GET /c HTTP/1.1" 200 1 "-" "-"\n'
            '5.5.5.5 - - [01/Jun/2026:00:00:04 +0000] "GET /a HTTP/1.1" 200 1 "-" "-"\n'
        )
        fname = self._create_temp_file(content)
        stats = process_file(fname)
        top = stats['top_endpoints']
        self.assertEqual(top[0], ('/a', 3))
        self.assertEqual(top[1], ('/b', 1))
        self.assertEqual(top[2], ('/c', 1))

    def test_process_file_handles_utf8_errors(self):
        # Simulate invalid UTF-8 bytes; we use errors='replace' so it won't crash.
        content = b'203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET /a HTTP/1.1" 200 100 "-" "-"\n'
        content += b'bad\xffbyte\n'  # invalid byte
        fname = self._create_temp_file(content.decode('utf-8', errors='replace'))  # we write as str with replacement
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(content)
            fname = f.name
            self.temp_files.append(fname)
        stats = process_file(fname)
        # The bad line should be replaced with � and then parsed as malformed.
        self.assertEqual(stats['bad_lines'], 1)  # the invalid line becomes garbage
        self.assertEqual(stats['total_requests'], 1)

if __name__ == '__main__':
    unittest.main()