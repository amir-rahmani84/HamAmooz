from cli import parse_arguments
from processor import process_file
from report import generate_report
from formatter import print_report
from parser import parse_timestamp
import sys
import json

# Helper to parse section/type strings into sets
def parse_list_string(s, valid_values, default_set):
    """
    Convert a comma-separated string to a set of valid values.
    If the string is 'all' or empty, return the default_set.
    """
    if not s or s.strip() == "":
        return default_set
    parts = [p.strip() for p in s.split(',') if p.strip()]
    if 'all' in parts:
        return default_set
    # Keep only valid values
    return set(p for p in parts if p in valid_values)

def main():
    args = parse_arguments()

    # Validate --top
    if args.top <= 0:
        print("Error: --top must be greater than 0.", file=sys.stderr)
        sys.exit(1)

    # Parse time range arguments
    start_time = None
    end_time = None
    if args.from_time:
        try:
            start_time = parse_timestamp(args.from_time)
        except ValueError as e:
            print(f"Error: Invalid timestamp for --from: {args.from_time}. {e}", file=sys.stderr)
            sys.exit(1)
    if args.to_time:
        try:
            end_time = parse_timestamp(args.to_time)
        except ValueError as e:
            print(f"Error: Invalid timestamp for --to: {args.to_time}. {e}", file=sys.stderr)
            sys.exit(1)

    if start_time is not None and end_time is not None and start_time > end_time:
        print("Error: --from time must be earlier than or equal to --to time.", file=sys.stderr)
        sys.exit(1)

    # Define valid sections and suspicious types
    valid_sections = {'basic', 'endpoints', 'hourly', 'suspicious', 'error-spikes'}
    valid_suspicious = {'brute_force', 'high_volume', 'high_error_rate', 'endpoint_scanning'}

    # Parse sections and suspicious-types once, converting to sets
    sections_set = parse_list_string(args.sections, valid_sections, valid_sections)
    suspicious_set = parse_list_string(args.suspicious_types, valid_suspicious, valid_suspicious)

    # Process file with the validated sets and time filters
    stats = process_file(args.logfile, sections_set=sections_set, suspicious_set=suspicious_set,
                         start_time=start_time, end_time=end_time)

    # Generate report with the same sets and top_n
    report = generate_report(stats, sections_set=sections_set, suspicious_set=suspicious_set,
                             top_n=args.top)

    # Output report
    if args.json:
        # Serialize report to JSON
        print(json.dumps(report, indent=2))
    else:
        print_report(report)


if __name__ == "__main__":
    main()