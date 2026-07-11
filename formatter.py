def print_report(report):
    """
    Print a nicely formatted report from the enriched stats dictionary.
    Only prints sections that are present in the report.
    """
    print("=" * 60)
    print("LOG ANALYSIS REPORT")
    print("=" * 60)

    # Basic section
    if 'total_requests' in report:
        print(f"\nTotal requests:        {report['total_requests']}")
    if 'bad_lines' in report:
        print(f"Malformed lines:       {report['bad_lines']}")
    if 'unique_ips' in report:
        print(f"Unique IP addresses:   {report['unique_ips']}")
    if 'error_requests' in report:
        print(f"Error requests (4xx/5xx): {report['error_requests']}")
    if 'error_rate' in report:
        print(f"Overall error rate:    {report['error_rate']:.2f}%")

    # Top endpoints
    if 'top_endpoints' in report:
        print(f"\nTop {len(report['top_endpoints'])} Endpoints:")
        print("-" * 40)
        for path, count in report['top_endpoints']:
            print(f"{path:>30} : {count}")

    # Hourly distribution
    if 'hourly_distribution' in report:
        print("\nHourly Request Distribution:")
        print("-" * 40)
        for hour, count in sorted(report['hourly_distribution'].items()):
            print(f"{hour:02d}:00 - {hour:02d}:59 : {count}")

    # Suspicious activities
    if 'suspicious_activities' in report:
        suspicious = report['suspicious_activities']
        if suspicious:
            print("\n" + "=" * 60)
            print("SUSPICIOUS ACTIVITY DETECTED")
            print("=" * 60)
            for act in suspicious:
                severity = act["severity"].upper()
                print(f"[{severity}] {act['type'].replace('_',' ').title()} from {act['ip']}")
                print(f"    {act['detail']}")
                print()
        else:
            print("\nNo suspicious activity detected.")

    # Error spikes
    if 'error_spikes' in report:
        error_spikes = report['error_spikes']
        if error_spikes:
            print("\n" + "=" * 60)
            print("ERROR SPIKE DETECTED")
            print("=" * 60)
            for start, end in error_spikes:
                # Format the date and time range
                if start == end:
                    # Single hour
                    print(f"{start.strftime('%d/%b/%Y %H:00')} – {start.strftime('%H:59')}")
                else:
                    # Multiple consecutive hours (start and end are datetime objects)
                    print(f"{start.strftime('%d/%b/%Y %H:00')} – {end.strftime('%d/%b/%Y %H:59')}")
        else:
            print("\nNo error spikes detected.")