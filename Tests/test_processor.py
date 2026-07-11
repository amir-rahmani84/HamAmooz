import unittest
from unittest.mock import patch, mock_open
import tempfile
import os
import gzip
from datetime import datetime
from processor import process_file
import config

class TestProcessor(unittest.TestCase):
    def setUp(self):
        # Create a temporary log file with sample lines
        self.log_lines = [
            '192.168.1.1 - - [01/Jun/2026:09:14:22 +0330] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
            '192.168.1.2 - - [01/Jun/2026:09:15:22 +0330] "GET /about HTTP/1.1" 505 567 "-" "curl/7.68"',
            '192.168.1.1 - - [01/Jun/2026:09:16:22 +0330] "POST /login HTTP/1.1" 401 123 "-" "Mozilla/5.0"',
            '192.168.1.3 - - [01/Jun/2026:10:00:00 +0330] "GET /index.html HTTP/1.1" 200 432 "-" "Mozilla/5.0"',
        ]
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        for line in self.log_lines:
            self.temp_file.write(line + '\n')
        self.temp_file.close()

    def tearDown(self):
        os.unlink(self.temp_file.name)

    def test_process_file_basic(self):
        stats = process_file(self.temp_file.name, sections_set={'basic'})
        self.assertEqual(stats['total_requests'], 4)
        self.assertEqual(stats['bad_lines'], 0)
        self.assertEqual(stats['unique_ips'], 3)   # 192.168.1.1, 1.2, 1.3
        self.assertEqual(stats['error_requests'], 2)  # 404 and 401

    def test_process_file_endpoints(self):
        stats = process_file(self.temp_file.name, sections_set={'endpoints'})
        self.assertIn('endpoint_counter', stats)
        counter = stats['endpoint_counter']
        self.assertEqual(counter['/index.html'], 2)
        self.assertEqual(counter['/about'], 1)
        self.assertEqual(counter['/login'], 1)

    def test_process_file_hourly(self):
        stats = process_file(self.temp_file.name, sections_set={'hourly'})
        self.assertIn('hourly_distribution', stats)
        dist = stats['hourly_distribution']
        self.assertEqual(dist[9], 3)   # three requests at hour 9
        self.assertEqual(dist[10], 1)  # one request at hour 10

    def test_process_file_time_filter(self):
        start = datetime(2026, 6, 1, 9, 15, 0, tzinfo=datetime.now().astimezone().tzinfo)
        end = datetime(2026, 6, 1, 9, 17, 0, tzinfo=datetime.now().astimezone().tzinfo)
        stats = process_file(self.temp_file.name, sections_set={'basic'},
                             start_time=start, end_time=end)
        self.assertEqual(stats['total_requests'], 2)   # only the 9:15 and 9:16 entries

    def test_process_file_strict_parser(self):
        stats = process_file(self.temp_file.name, sections_set={'basic'}, strict_parser=True)
        self.assertEqual(stats['total_requests'], 4)   # all lines are valid

    def test_process_file_malformed_line(self):
        # Add a malformed line to the file
        with open(self.temp_file.name, 'a', encoding='utf-8') as f:
            f.write('garbage line\n')
        stats = process_file(self.temp_file.name, sections_set={'basic'})
        self.assertEqual(stats['total_requests'], 4)   # only valid lines
        self.assertEqual(stats['bad_lines'], 1)

    def test_process_file_suspicious_collection(self):
        stats = process_file(self.temp_file.name,
                             sections_set={'suspicious'},
                             suspicious_set={'brute_force', 'high_volume'})
        # Check that the required structures exist
        self.assertIn('failed_logins', stats)
        self.assertEqual(stats['failed_logins']['192.168.1.1'], 1)  # one failed login
        self.assertIn('requests_per_ip', stats)
        self.assertEqual(stats['requests_per_ip']['192.168.1.1'], 2)

    def test_process_file_error_spikes(self):
        stats = process_file(self.temp_file.name, sections_set={'error-spikes'})
        self.assertIn('total_by_dt_hour', stats)
        self.assertIn('error_by_dt_hour', stats)
        # Check that a bucket exists for hour 9
        key = (datetime(2026, 6, 1).date(), 9)
        self.assertIn(key, stats['total_by_dt_hour'])
        self.assertEqual(stats['total_by_dt_hour'][key], 3)
        self.assertEqual(stats['error_by_dt_hour'][key], 1)  # only 505 at hour 9

    @patch('processor.gzip.open')
    def test_process_file_gzip(self, mock_gzip):
        # Simulate a gzip file
        mock_gzip.return_value = mock_open(read_data='\n'.join(self.log_lines))()
        stats = process_file('dummy.log.gz', sections_set={'basic'})
        self.assertEqual(stats['total_requests'], 4)
        mock_gzip.assert_called_once_with('dummy.log.gz', 'rt', encoding='utf-8', errors='replace')

if __name__ == '__main__':
    unittest.main()