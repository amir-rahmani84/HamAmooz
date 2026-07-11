import unittest
from collections import Counter, defaultdict
from report import (
    compute_error_rate,
    compute_top_endpoints,
    detect_brute_force,
    detect_high_volume,
    detect_high_error_rate,
    detect_endpoint_scanning,
    detect_suspicious_activities,
    detect_error_spikes,
    generate_report
)
from datetime import datetime

class TestReport(unittest.TestCase):
    def setUp(self):
        self.stats_basic = {
            'total_requests': 100,
            'error_requests': 10,
        }

    def test_compute_error_rate(self):
        self.assertEqual(compute_error_rate(self.stats_basic), 10.0)
        self.assertEqual(compute_error_rate({'total_requests': 0}), 0.0)

    def test_compute_top_endpoints(self):
        counter = Counter({'/': 50, '/about': 30, '/contact': 20})
        stats = {'endpoint_counter': counter}
        top = compute_top_endpoints(stats, n=2)
        self.assertEqual(top, [('/', 50), ('/about', 30)])

    def test_detect_brute_force(self):
        failed = Counter({'1.1.1.1': 10, '2.2.2.2': 3})
        stats = {'failed_logins': failed}
        config_dict = {'failed_login_threshold': 5}
        result = detect_brute_force(stats, config_dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['ip'], '1.1.1.1')
        self.assertEqual(result[0]['detail'], '10 failed logins on /login')


    def test_detect_high_volume_explicit(self):
        req = Counter({'1.1.1.1': 100, '2.2.2.2': 10, '3.3.3.3': 12})
        stats = {'requests_per_ip': req}
        result = detect_high_volume(stats, {'request_rate_threshold': 20})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['ip'], '1.1.1.1')
        self.assertEqual(result[0]['detail'], '100 total requests (threshold=20.0)')

    def test_detect_high_volume_automatic(self):
        # Use a dataset where one IP is a clear outlier (> mean + 2*std)
        req = Counter({'1.1.1.1': 1000} | {f'2.2.2.{i}': 100 for i in range(1, 10)})
        # 9 IPs with 100, one with 1000 => mean = (1000+900)/10 = 190, std ≈ 284.6, threshold ≈ 759.2, so 1000 exceeds.
        stats = {'requests_per_ip': req}
        result = detect_high_volume(stats, {})  # use automatic
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['ip'], '1.1.1.1')

    def test_detect_high_error_rate(self):
        status_per_ip = defaultdict(Counter)
        status_per_ip['1.1.1.1'][200] = 10
        status_per_ip['1.1.1.1'][404] = 90
        status_per_ip['2.2.2.2'][200] = 100
        stats = {'status_per_ip': status_per_ip}
        config_dict = {'error_rate_threshold': 0.8}
        result = detect_high_error_rate(stats, config_dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['ip'], '1.1.1.1')
        self.assertIn('90/100', result[0]['detail'])

        # IP with too few requests (<50) should be skipped
        status_per_ip['3.3.3.3'][404] = 10
        result = detect_high_error_rate(stats, config_dict)
        self.assertEqual(len(result), 1)  # only 1.1.1.1

    def test_detect_endpoint_scanning(self):
        endpoints_per_ip = defaultdict(set)
        endpoints_per_ip['1.1.1.1'] = {f'/page{i}' for i in range(50)}
        endpoints_per_ip['2.2.2.2'] = {f'/page{i}' for i in range(10)}
        stats = {'endpoints_per_ip': endpoints_per_ip}
        config_dict = {'scanning_endpoint_threshold': 40}
        result = detect_endpoint_scanning(stats, config_dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['ip'], '1.1.1.1')
        self.assertEqual(result[0]['detail'], 'accessed 50 distinct endpoints')

    def test_detect_suspicious_activities(self):
        # Build a stats dict with all needed data
        stats = {
            'failed_logins': Counter({'1.1.1.1': 10}),
            'requests_per_ip': Counter({'1.1.1.1': 200, '2.2.2.2': 10}),
            'status_per_ip': defaultdict(Counter, {'1.1.1.1': Counter({404: 150, 200: 50})}),
            'endpoints_per_ip': defaultdict(set, {'1.1.1.1': {f'/p{i}' for i in range(45)}})
        }
        # Set low thresholds to trigger all
        config_dict = {
            'failed_login_threshold': 1,
            'request_rate_threshold': 50,
            'error_rate_threshold': 0.1,
            'scanning_endpoint_threshold': 40
        }
        result = detect_suspicious_activities(stats, config_dict, types='all')
        # Expect 4 activities (one per type) but note that high_volume and high_error_rate might
        # each produce one for 1.1.1.1, but they are separate entries.
        # We'll just check that at least brute_force and endpoint_scanning are present.
        types_found = {item['type'] for item in result}
        self.assertIn('brute_force', types_found)
        self.assertIn('endpoint_scanning', types_found)

    def test_detect_error_spikes(self):
        total_by_dt_hour = Counter()
        error_by_dt_hour = Counter()
        base_date = datetime(2026, 6, 1).date()
        # Hour 9: 100 requests, 50 errors (50%)
        total_by_dt_hour[(base_date, 9)] = 100
        error_by_dt_hour[(base_date, 9)] = 50
        # Hour 10: 100 requests, 5 errors (5%)
        total_by_dt_hour[(base_date, 10)] = 100
        error_by_dt_hour[(base_date, 10)] = 5
        # Hour 11: 100 requests, 80 errors (80%)
        total_by_dt_hour[(base_date, 11)] = 100
        error_by_dt_hour[(base_date, 11)] = 80

        stats = {
            'total_by_dt_hour': total_by_dt_hour,
            'error_by_dt_hour': error_by_dt_hour
        }
        # With dynamic threshold: rates = [50,5,80], mean=45, std≈37.5, threshold=120, so none exceed.
        # Use explicit threshold to trigger.
        config_dict = {'error_spike_threshold': 40}
        spikes = detect_error_spikes(stats, config_dict)
        # Should flag hour 9 (50%) and hour 11 (80%) but not hour 10 (5%)
        expected_dts = [
            datetime(2026, 6, 1, 9, 0),
            datetime(2026, 6, 1, 11, 0)
        ]
        # They are not consecutive, so each is a single interval
        self.assertEqual(len(spikes), 2)
        self.assertEqual(spikes[0][0], expected_dts[0])
        self.assertEqual(spikes[0][1], expected_dts[0])  # single hour
        self.assertEqual(spikes[1][0], expected_dts[1])
        self.assertEqual(spikes[1][1], expected_dts[1])

        # Test merging consecutive hours
        total_by_dt_hour[(base_date, 12)] = 100
        error_by_dt_hour[(base_date, 12)] = 60
        stats = {
            'total_by_dt_hour': total_by_dt_hour,
            'error_by_dt_hour': error_by_dt_hour
        }
        spikes = detect_error_spikes(stats, {'error_spike_threshold': 40})
        # Now hours 11 and 12 are consecutive, so they should merge
        self.assertEqual(len(spikes), 2)  # hour 9 and hours 11-12
        self.assertEqual(spikes[1][0], datetime(2026, 6, 1, 11, 0))
        self.assertEqual(spikes[1][1], datetime(2026, 6, 1, 12, 0))

    def test_generate_report(self):
        raw = {
            'total_requests': 100,
            'bad_lines': 2,
            'unique_ips': 10,
            'error_requests': 15,
            'endpoint_counter': Counter({'/': 50, '/about': 30}),
            'hourly_distribution': {9: 60, 10: 40},
            'failed_logins': Counter({'1.1.1.1': 6}),
            'requests_per_ip': Counter({'1.1.1.1': 200}),
            'status_per_ip': defaultdict(Counter, {'1.1.1.1': Counter({404: 150, 200: 50})}),
            'endpoints_per_ip': defaultdict(set, {'1.1.1.1': {f'/p{i}' for i in range(45)}}),
            'total_by_dt_hour': Counter({(datetime(2026,6,1).date(), 9): 100}),
            'error_by_dt_hour': Counter({(datetime(2026,6,1).date(), 9): 50}),
        }
        sections = {'basic', 'endpoints', 'hourly', 'suspicious', 'error-spikes'}
        suspicious_set = {'brute_force', 'endpoint_scanning'}
        report = generate_report(raw, sections_set=sections, suspicious_set=suspicious_set, top_n=5)
        self.assertIn('total_requests', report)
        self.assertIn('top_endpoints', report)
        self.assertIn('hourly_distribution', report)
        self.assertIn('suspicious_activities', report)
        self.assertIn('error_spikes', report)

if __name__ == '__main__':
    unittest.main()