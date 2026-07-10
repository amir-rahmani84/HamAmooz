from collections import Counter, defaultdict
from parser import parse_line
import gzip


def process_file(file_path, sections_set=None, suspicious_set=None):
    """
    Process a log file and return raw statistics counters.
    Only collects data that is needed based on the provided sections and suspicious types.
    No analysis is performed here – only collection of raw data.
    """
    # Default to all if not provided (though main should always provide)
    if sections_set is None:
        sections_set = {'basic', 'endpoints', 'hourly', 'suspicious', 'error-spikes'}
    if suspicious_set is None:
        suspicious_set = {'brute_force', 'high_volume', 'high_error_rate', 'endpoint_scanning'}

    # Determine which high-level sections are enabled
    need_basic = 'basic' in sections_set
    need_endpoints = 'endpoints' in sections_set
    need_hourly = 'hourly' in sections_set
    need_error_spikes = 'error-spikes' in sections_set
    need_suspicious = 'suspicious' in sections_set

    # Determine which specific suspicious data structures are needed
    need_failed_logins = need_suspicious and 'brute_force' in suspicious_set
    need_requests_per_ip = need_suspicious and 'high_volume' in suspicious_set
    need_status_per_ip = need_suspicious and 'high_error_rate' in suspicious_set
    need_endpoints_per_ip = need_suspicious and 'endpoint_scanning' in suspicious_set

    # Hourly counters needed for hourly distribution and error spikes
    need_hour_counter = need_hourly or need_error_spikes
    need_error_hour_counter = need_error_spikes

    # Initialize counters only if needed
    total_requests = 0
    bad_lines = 0
    error_requests = 0
    unique_ips = set()

    endpoint_counter = Counter() if need_endpoints else None
    hour_counter = Counter() if need_hour_counter else None
    error_hour_counter = Counter() if need_error_hour_counter else None

    # Suspicious data structures – allocate only when required
    requests_per_ip = Counter() if need_requests_per_ip else None
    status_per_ip = defaultdict(Counter) if need_status_per_ip else None
    endpoints_per_ip = defaultdict(set) if need_endpoints_per_ip else None
    failed_logins = Counter() if need_failed_logins else None

    # Detect if the file is compressed (ends with .gz)
    try:
        if file_path.endswith('.gz'):
            file_obj = gzip.open(file_path, 'rt', encoding='utf-8', errors='replace')
        else:
            file_obj = open(file_path, 'rt', encoding='utf-8', errors='replace')
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}")
    except IsADirectoryError:
        raise IsADirectoryError(f"Path is a directory, not a file: {file_path}")
    except PermissionError:
        raise PermissionError(f"Permission denied reading file: {file_path}")
    except gzip.BadGzipFile:
        raise ValueError(f"File has .gz extension but is not a valid gzip file: {file_path}")
    except OSError as e:
        raise OSError(f"Error opening file {file_path}: {e}")

    with file_obj:
        for line in file_obj:
            line = line.rstrip()
            entry = parse_line(line)

            if entry is None:
                if need_basic:
                    bad_lines += 1
                continue

            # Conditionally update counters based on which data is needed
            if need_basic:
                total_requests += 1
                unique_ips.add(entry.ip)
                if 400 <= entry.status < 600:
                    error_requests += 1

            if need_endpoints:
                endpoint_counter[entry.path] += 1

            if need_hour_counter:
                hour_counter[entry.timestamp.hour] += 1

            if need_error_hour_counter and 500 <= entry.status < 600:
                error_hour_counter[entry.timestamp.hour] += 1

            # Suspicious data updates – each only if needed
            if need_requests_per_ip:
                requests_per_ip[entry.ip] += 1

            if need_status_per_ip:
                status_per_ip[entry.ip][entry.status] += 1

            if need_endpoints_per_ip:
                endpoints_per_ip[entry.ip].add(entry.path)

            if need_failed_logins and entry.path == '/login' and entry.status == 401:
                failed_logins[entry.ip] += 1

    # Build stats dict with only the collected data
    stats = {}
    if need_basic:
        stats['total_requests'] = total_requests
        stats['bad_lines'] = bad_lines
        stats['unique_ips'] = len(unique_ips)
        stats['error_requests'] = error_requests
    if need_endpoints:
        stats['endpoint_counter'] = endpoint_counter
    if need_hour_counter:
        stats['hourly_distribution'] = hour_counter
    if need_error_hour_counter:
        stats['error_hour_counter'] = error_hour_counter
    if need_requests_per_ip:
        stats['requests_per_ip'] = requests_per_ip
    if need_status_per_ip:
        stats['status_per_ip'] = status_per_ip
    if need_endpoints_per_ip:
        stats['endpoints_per_ip'] = endpoints_per_ip
    if need_failed_logins:
        stats['failed_logins'] = failed_logins

    return stats