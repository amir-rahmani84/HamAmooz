from collections import Counter
from parser import parse_line


def process_file(file_path):

    total_requests = 0
    bad_lines = 0
    error_requests = 0

    unique_ips = set()
    endpoint_counter = Counter()
    hour_counter = Counter()

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

    # this shouldnt happen but if we do not get any valid entries
    # we handle the division of zero like this
    if total_requests == 0:
        error_rate = 0.0
    else:
        error_rate = (error_requests / total_requests) * 100

    # Basic report
    # might save the Results in a file later on
    print(f"Total Requests      : {total_requests}")
    print(f"Malformed Lines     : {bad_lines}")
    print(f"Unique IPs          : {len(unique_ips)}")
    print(f"Hourly distribution : {hour_counter}")
    print(f"Error Rate          : {error_rate:.2f}%")
    print(endpoint_counter.most_common(10))