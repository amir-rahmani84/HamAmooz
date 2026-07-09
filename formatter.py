# this might change from printing format to saving to a file
# also might add more options for the report
def print_report(report):

    print("=" * 40)
    print("Access Log Report")
    print("=" * 40)

    print(f"Total Requests : {report['total_requests']}")
    print(f"Malformed Lines: {report['bad_lines']}")
    print(f"Unique IPs     : {report['unique_ips']}")
    print(f"Error Rate     : {report['error_rate']:.2f}%")

    print()

    print("Top 10 Endpoints")
    print("-" * 40)

    for path, count in report["top_endpoints"]:
        print(f"{count:>6}  {path}")

    print()

    print("Hourly Traffic")
    print("-" * 40)

    hours = report["hourly_distribution"]

    max_requests = max(hours.values(), default=0)
    MAX_BAR_WIDTH = 50

    for hour in range(24):

        count = hours.get(hour, 0)

        if max_requests == 0:
            bar = ""
        else:
            length = int(count / max_requests * MAX_BAR_WIDTH)
            bar = "#" * length

        print(f"{hour:02d}: {count:5} | {bar}")