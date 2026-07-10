import statistics
from collections import Counter
import config

def compute_error_rate(stats):
    """Compute overall error rate from raw stats."""
    total = stats.get("total_requests", 0)
    errors = stats.get("error_requests", 0)
    if total == 0:
        return 0.0
    return (errors / total) * 100


def compute_top_endpoints(stats, n=10):
    """Return the top N endpoints by request count."""
    counter = stats.get("endpoint_counter")
    if counter is None:
        return []
    return counter.most_common(n)


def detect_brute_force(stats, config_dict):
    """
    Detect brute-force attempts (excessive failed logins on /login).
    Returns a list of suspicious activity dicts.
    """
    suspicious = []
    failed = stats.get("failed_logins")
    if failed is None:
        return suspicious
    threshold = config_dict.get("failed_login_threshold", config.FAILED_LOGIN_THRESHOLD)
    for ip, count in failed.items():
        if count > threshold:
            suspicious.append({
                "type": "brute_force",
                "ip": ip,
                "detail": f"{count} failed logins on /login",
                "severity": "high"
            })
    return suspicious


def detect_high_volume(stats, config_dict):
    """
    Detect IPs with unusually high request volume (DDoS / scraping).
    Returns a list of suspicious activity dicts.
    """
    suspicious = []
    req_per_ip = stats.get("requests_per_ip")
    if not req_per_ip:
        return suspicious

    values = list(req_per_ip.values())
    mean = statistics.mean(values)
    std = statistics.stdev(values) if len(values) > 1 else 0

    threshold_vol = config_dict.get("request_rate_threshold")
    if threshold_vol is None:
        threshold_vol = mean + 2 * std

    for ip, count in req_per_ip.items():
        if count > threshold_vol:
            suspicious.append({
                "type": "high_volume",
                "ip": ip,
                "detail": f"{count} total requests (threshold={threshold_vol:.1f})",
                "severity": "medium"
            })
    return suspicious


def detect_high_error_rate(stats, config_dict):
    """
    Detect IPs with a high proportion of error responses (status >= 400).
    Returns a list of suspicious activity dicts.
    """
    suspicious = []
    threshold = config_dict.get("error_rate_threshold", config.ERROR_RATE_THRESHOLD)
    status_per_ip = stats.get("status_per_ip")
    if status_per_ip is None:
        return suspicious

    for ip, status_counts in status_per_ip.items():
        total = sum(status_counts.values())
        errors = sum(v for status, v in status_counts.items() if status >= 400)
        if total > 50:
            error_ratio = errors / total
            if error_ratio > threshold:
                suspicious.append({
                    "type": "high_error_rate",
                    "ip": ip,
                    "detail": f"{errors}/{total} requests resulted in errors ({error_ratio:.1%})",
                    "severity": "medium"
                })
    return suspicious


def detect_endpoint_scanning(stats, config_dict):
    """
    Detect IPs that access an unusually high number of distinct endpoints.
    Returns a list of suspicious activity dicts.
    """
    suspicious = []
    threshold = config_dict.get("scanning_endpoint_threshold", config.SCANNING_ENDPOINT_THRESHOLD)
    endpoints_per_ip = stats.get("endpoints_per_ip")
    if endpoints_per_ip is None:
        return suspicious

    for ip, endpoints in endpoints_per_ip.items():
        if len(endpoints) > threshold:
            suspicious.append({
                "type": "endpoint_scanning",
                "ip": ip,
                "detail": f"accessed {len(endpoints)} distinct endpoints",
                "severity": "medium"
            })
    return suspicious


def detect_suspicious_activities(stats, config_dict=None, types=None):
    """
    Detect various suspicious patterns from the raw statistics.
    Aggregates results from individual detection functions.

    config: dict with thresholds, e.g.
        {
            "failed_login_threshold": 5,
            "request_rate_threshold": None,   # if None, use mean + 2*std
            "error_rate_threshold": 0.8,
            "scanning_endpoint_threshold": 40,
        }
    types: set or list of specific detection types to include (e.g., {'brute_force'}).
           If None or 'all', include all.
    """
    if config_dict is None:
        config_dict = {
            "failed_login_threshold": config.FAILED_LOGIN_THRESHOLD,
            "request_rate_threshold": None,
            "error_rate_threshold": config.ERROR_RATE_THRESHOLD,
            "scanning_endpoint_threshold": config.SCANNING_ENDPOINT_THRESHOLD,
        }

    # Determine which detection functions to run
    all_types = {
        'brute_force': detect_brute_force,
        'high_volume': detect_high_volume,
        'high_error_rate': detect_high_error_rate,
        'endpoint_scanning': detect_endpoint_scanning,
    }
    if types is None or 'all' in types:
        selected = all_types.values()
    else:
        # types can be a set or list
        selected = [all_types[t] for t in types if t in all_types]

    suspicious = []
    for detector in selected:
        suspicious.extend(detector(stats, config_dict))

    return suspicious


def detect_error_spikes(stats, config_dict):
    """
    Detect hours where the 5xx error rate exceeds a threshold.
    Returns a list of (start_hour, end_hour) intervals (consecutive hours).
    """
    hour_counter = stats.get("hourly_distribution")
    error_hour_counter = stats.get("error_hour_counter")
    if hour_counter is None or error_hour_counter is None:
        return []

    hours_with_requests = [h for h, count in hour_counter.items() if count > 0]
    if not hours_with_requests:
        return []

    # Compute error rate (%) for each such hour
    error_rates = {}
    for h in hours_with_requests:
        total = hour_counter[h]
        errors = error_hour_counter.get(h, 0)
        error_rates[h] = (errors / total) * 100.0

    # Determine threshold: use config value if provided, else dynamic (mean + 2*std)
    threshold = config_dict.get("error_spike_threshold")
    if threshold is None:
        rates = list(error_rates.values())
        mean = statistics.mean(rates)
        std = statistics.stdev(rates) if len(rates) > 1 else 0.0
        threshold = mean + 2 * std

    # Find hours exceeding threshold
    spike_hours = sorted([h for h, rate in error_rates.items() if rate > threshold])

    # Group consecutive hours into intervals
    intervals = []
    if spike_hours:
        start = spike_hours[0]
        end = spike_hours[0]
        for h in spike_hours[1:]:
            if h == end + 1:
                end = h
            else:
                intervals.append((start, end))
                start = end = h
        intervals.append((start, end))

    return intervals


def generate_report(raw_stats, sections_set=None, suspicious_set=None, top_n=10):
    """
    Combine raw stats with computed analysis and return a complete report dict.
    Only computes sections that are requested (default: all).
    """
    # Default to all if not provided
    if sections_set is None:
        sections_set = config.VALID_SECTIONS
    if suspicious_set is None:
        suspicious_set = config.VALID_SUSPICIOUS

    report = {}

    # Basic section
    if 'basic' in sections_set:
        report['total_requests'] = raw_stats.get('total_requests', 0)
        report['bad_lines'] = raw_stats.get('bad_lines', 0)
        report['unique_ips'] = raw_stats.get('unique_ips', 0)
        report['error_requests'] = raw_stats.get('error_requests', 0)
        report['error_rate'] = compute_error_rate(raw_stats)

    # Endpoints section
    if 'endpoints' in sections_set and 'endpoint_counter' in raw_stats:
        report['top_endpoints'] = compute_top_endpoints(raw_stats, n=top_n)

    # Hourly section
    if 'hourly' in sections_set and 'hourly_distribution' in raw_stats:
        report['hourly_distribution'] = raw_stats['hourly_distribution']

    # Suspicious section
    if 'suspicious' in sections_set:
        # The raw_stats should contain the necessary data if the processor collected it.
        # The detection functions gracefully handle missing data and return empty lists.
        report['suspicious_activities'] = detect_suspicious_activities(
            raw_stats, types=suspicious_set
        )

    # Error spikes section
    if 'error-spikes' in sections_set:
        if 'hourly_distribution' in raw_stats and 'error_hour_counter' in raw_stats:
            report['error_spikes'] = detect_error_spikes(raw_stats, {})
        else:
            report['error_spikes'] = []

    return report