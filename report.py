import statistics
from collections import Counter


def compute_error_rate(stats):
    """Compute overall error rate from raw stats."""
    total = stats["total_requests"]
    errors = stats["error_requests"]
    if total == 0:
        return 0.0
    return (errors / total) * 100


def compute_top_endpoints(stats, n=10):
    """Return the top N endpoints by request count."""
    counter = stats["endpoint_counter"]
    return counter.most_common(n)


def detect_brute_force(stats, config):
    """
    Detect brute-force attempts (excessive failed logins on /login).
    Returns a list of suspicious activity dicts.
    """
    suspicious = []
    failed = stats["failed_logins"]
    threshold = config.get("failed_login_threshold", 5)
    for ip, count in failed.items():
        if count > threshold:
            suspicious.append({
                "type": "brute_force",
                "ip": ip,
                "detail": f"{count} failed logins on /login",
                "severity": "high"
            })
    return suspicious


def detect_high_volume(stats, config):
    """
    Detect IPs with unusually high request volume (DDoS / scraping).
    Returns a list of suspicious activity dicts.
    """
    suspicious = []
    req_per_ip = stats["requests_per_ip"]
    if not req_per_ip:
        return suspicious

    values = list(req_per_ip.values())
    mean = statistics.mean(values)
    std = statistics.stdev(values) if len(values) > 1 else 0

    threshold_vol = config.get("request_rate_threshold")
    if threshold_vol is None:
        # this is not a good implementation but since we are not using the 
        # timestamps it should be fine for now (using a fixed number works at this time aswell)
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


def detect_high_error_rate(stats, config):
    """
    Detect IPs with a high proportion of error responses (status >= 400).
    Returns a list of suspicious activity dicts.
    """
    suspicious = []
    threshold = config.get("error_rate_threshold", 0.8)

    for ip, status_counts in stats["status_per_ip"].items():
        total = sum(status_counts.values())
        errors = sum(v for status, v in status_counts.items() if status >= 400)
        # if the total amount of requests are not high the error ratio is not suspicious
        # AGAIN since we are  not using timestamps this should suffice for now
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


def detect_endpoint_scanning(stats, config):
    """
    Detect IPs that access an unusually high number of distinct endpoints.
    Returns a list of suspicious activity dicts.
    """
    suspicious = []
    threshold = config.get("scanning_endpoint_threshold", 20)

    for ip, endpoints in stats["endpoints_per_ip"].items():
        # AGAIN usually we care more about sensitive Ips and the time window of requests
        # this should suffice for now
        if len(endpoints) > threshold:
            suspicious.append({
                "type": "endpoint_scanning",
                "ip": ip,
                "detail": f"accessed {len(endpoints)} distinct endpoints",
                "severity": "medium"
            })
    return suspicious


def detect_suspicious_activities(stats, config=None):
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
    """
    if config is None:
        config = {
            "failed_login_threshold": 5,
            "request_rate_threshold": None,
            "error_rate_threshold": 0.8,
            "scanning_endpoint_threshold": 40,
        }

    suspicious = []
    suspicious.extend(detect_brute_force(stats, config))
    suspicious.extend(detect_high_volume(stats, config))
    suspicious.extend(detect_high_error_rate(stats, config))
    suspicious.extend(detect_endpoint_scanning(stats, config))

    # Additional checks can be added here by calling new detection functions.

    return suspicious


def detect_error_spikes(stats, config):
    """
    Detect hours where the 5xx error rate exceeds a threshold.
    Returns a list of (start_hour, end_hour) intervals (consecutive hours).
    """
    hour_counter = stats["hourly_distribution"]      # all requests per hour
    error_hour_counter = stats["error_hour_counter"] # 5xx errors per hour

    # Only consider hours that actually received requests
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
    threshold = config.get("error_spike_threshold")
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


def generate_report(raw_stats, config=None):
    """
    Combine raw stats with computed analysis and return a complete report dict.
    """
    if config is None:
        config = {
            "failed_login_threshold": 5,
            "request_rate_threshold": None,
            "error_rate_threshold": 0.8,
            "scanning_endpoint_threshold": 40,
            "error_spike_threshold": None,   # None → dynamic (mean + 2*std)
        }

    report = {
        "total_requests": raw_stats["total_requests"],
        "bad_lines": raw_stats["bad_lines"],
        "unique_ips": raw_stats["unique_ips"],
        "error_requests": raw_stats["error_requests"],
        "error_rate": compute_error_rate(raw_stats),
        "top_endpoints": compute_top_endpoints(raw_stats),
        "hourly_distribution": raw_stats["hourly_distribution"],
        "suspicious_activities": detect_suspicious_activities(raw_stats, config),
        "error_spikes": detect_error_spikes(raw_stats, config),   # <-- new key
    }
    return report