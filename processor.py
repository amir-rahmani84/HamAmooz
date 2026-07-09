from collections import Counter, defaultdict
from parser import parse_line


def process_file(file_path):
    """
    Process a log file and return raw statistics counters.
    No analysis is performed here – only collection of raw data.
    """

    total_requests = 0
    bad_lines = 0
    error_requests = 0

    unique_ips = set()                   # total unique IPs
    endpoint_counter = Counter()         # total calls per endpoint
    hour_counter = Counter()             # total requests per hour
    requests_per_ip = Counter()          # total requests per IP
    status_per_ip = defaultdict(Counter) # status code distribution per IP
    endpoints_per_ip = defaultdict(set)  # distinct endpoints accessed per IP
    failed_logins = Counter()            # 401 on /login per IP

    # we use errors="replace" so if the file contains invalid utf-8 bytes the function doesnt crash
    with open(file_path, "r", encoding="utf-8", errors="replace") as file:

        for line in file:

            # Remove the new line character from entry
            line = line.rstrip("\n")

            entry = parse_line(line)

            if entry is None:
                # Update Malformed entries
                bad_lines += 1
                continue
            
            # Update total amount of entries
            total_requests += 1

            # Adds the entry IP if it is a new one
            unique_ips.add(entry.ip)

            # List the amount of requests for each endpoint
            endpoint_counter[entry.path] += 1

            # Update hourly rate of requests
            hour_counter[entry.timestamp.hour] += 1

            # Updates the amount of requests with errors
            # we can differentiate the Errors Later if need be
            if 400 <= entry.status < 600:
                error_requests += 1

            # --- Collect raw per‑IP data for later analysis ---
            ip = entry.ip
            requests_per_ip[ip] += 1
            status_per_ip[ip][entry.status] += 1
            endpoints_per_ip[ip].add(entry.path)

            # Specific detection: failed logins (raw counter)
            if entry.path == '/login' and entry.status == 401:
                failed_logins[ip] += 1

    # Return only raw data – no derived metrics
    return {
        "total_requests": total_requests,
        "bad_lines": bad_lines,
        "unique_ips": len(unique_ips),
        "error_requests": error_requests,
        "hourly_distribution": hour_counter,
        "endpoint_counter": endpoint_counter,
        # raw per‑IP data
        "requests_per_ip": requests_per_ip,
        "status_per_ip": status_per_ip,
        "endpoints_per_ip": endpoints_per_ip,
        "failed_logins": failed_logins,
    }