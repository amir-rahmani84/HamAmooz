import unittest
from unittest.mock import patch
import argparse
from cli import parse_arguments

class TestCLI(unittest.TestCase):
    @patch('argparse.ArgumentParser.parse_args')
    def test_parse_arguments_defaults(self, mock_parse):
        # Simulate default args
        mock_parse.return_value = argparse.Namespace(
            logfile='access.log',
            sections='basic,endpoints,hourly',
            suspicious_types='brute_force',
            top=10,
            from_time=None,
            to_time=None,
            json=False,
            output=None,
            strict_parser=False
        )
        args = parse_arguments()
        self.assertEqual(args.logfile, 'access.log')
        self.assertEqual(args.sections, 'basic,endpoints,hourly')
        self.assertEqual(args.suspicious_types, 'brute_force')
        self.assertEqual(args.top, 10)
        self.assertIsNone(args.from_time)
        self.assertIsNone(args.to_time)
        self.assertFalse(args.json)
        self.assertIsNone(args.output)
        self.assertFalse(args.strict_parser)

    @patch('argparse.ArgumentParser.parse_args')
    def test_parse_arguments_custom(self, mock_parse):
        mock_parse.return_value = argparse.Namespace(
            logfile='custom.log',
            sections='all',
            suspicious_types='high_volume,high_error_rate',
            top=20,
            from_time='01/Jun/2026:00:00:00 +0000',
            to_time='02/Jun/2026:00:00:00 +0000',
            json=True,
            output='report.json',
            strict_parser=True
        )
        args = parse_arguments()
        self.assertEqual(args.logfile, 'custom.log')
        self.assertEqual(args.sections, 'all')
        self.assertEqual(args.suspicious_types, 'high_volume,high_error_rate')
        self.assertEqual(args.top, 20)
        self.assertEqual(args.from_time, '01/Jun/2026:00:00:00 +0000')
        self.assertEqual(args.to_time, '02/Jun/2026:00:00:00 +0000')
        self.assertTrue(args.json)
        self.assertEqual(args.output, 'report.json')
        self.assertTrue(args.strict_parser)

    @patch('argparse.ArgumentParser.parse_args')
    def test_parse_arguments_with_output_no_json(self, mock_parse):
        mock_parse.return_value = argparse.Namespace(
            logfile='access.log',
            sections='basic',
            suspicious_types='brute_force',
            top=10,
            from_time=None,
            to_time=None,
            json=False,
            output='out.json',
            strict_parser=False
        )
        args = parse_arguments()
        self.assertFalse(args.json)
        self.assertEqual(args.output, 'out.json')

if __name__ == '__main__':
    unittest.main()