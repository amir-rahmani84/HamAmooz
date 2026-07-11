from cli import parse_arguments
from processor import process_file
from report import generate_report
from formatter import print_report
from parser import parse_timestamp
import sys
import json
import time
import os  # for directory creation
import config
import gzip


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
    # Record start time for performance measurement
    start_time_total = time.time()

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

    # Define valid sections and suspicious types - now imported from config
    valid_sections = config.VALID_SECTIONS
    valid_suspicious = config.VALID_SUSPICIOUS

    # Validate --sections
    sections_raw = args.sections
    sections_parts = [p.strip() for p in sections_raw.split(',') if p.strip()]
    sections_to_validate = [p for p in sections_parts if p != 'all']
    invalid_sections = set(sections_to_validate) - valid_sections
    if invalid_sections:
        print(f"Error: Unknown section(s): {', '.join(invalid_sections)}", file=sys.stderr)
        print(f"Allowed sections: {', '.join(sorted(valid_sections))} or 'all'", file=sys.stderr)
        sys.exit(1)

    # Validate --suspicious-types
    susp_raw = args.suspicious_types
    susp_parts = [p.strip() for p in susp_raw.split(',') if p.strip()]
    susp_to_validate = [p for p in susp_parts if p != 'all']
    invalid_susp = set(susp_to_validate) - valid_suspicious
    if invalid_susp:
        print(f"Error: Unknown suspicious type(s): {', '.join(invalid_susp)}", file=sys.stderr)
        print(f"Allowed types: {', '.join(sorted(valid_suspicious))} or 'all'", file=sys.stderr)
        sys.exit(1)

    # Parse sections and suspicious-types once, converting to sets
    sections_set = parse_list_string(args.sections, valid_sections, valid_sections)
    suspicious_set = parse_list_string(args.suspicious_types, valid_suspicious, valid_suspicious)

    # Process file with the validated sets, time filters, and parser mode
    try:
        stats = process_file(args.logfile, sections_set=sections_set, suspicious_set=suspicious_set,
                             start_time=start_time, end_time=end_time,
                             strict_parser=args.strict_parser)
    except (FileNotFoundError, PermissionError, IsADirectoryError, ValueError, OSError, gzip.BadGzipFile) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Generate report with the same sets and top_n
    try:
        report = generate_report(stats, sections_set=sections_set, suspicious_set=suspicious_set,
                                 top_n=args.top)
    except Exception as e:
        print(f"Error generating report: {e}", file=sys.stderr)
        sys.exit(1)

    # Handle output
    # If --output is given, write JSON to the specified file
    if args.output:
        try:
            # Ensure the directory exists
            output_dir = os.path.dirname(args.output)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
        except Exception as e:
            print(f"Error writing to output file '{args.output}': {e}", file=sys.stderr)
            sys.exit(1)

    # Decide what to print to stdout
    if args.json:
        # JSON to stdout (regardless of --output, we print it)
        print(json.dumps(report, indent=2))
    elif not args.output:
        # No --output and no --json -> print formatted text
        print_report(report)
    # If args.output is given and --json is False, we print nothing (only stderr)

    # Record end time and report execution time to stderr
    end_time_total = time.time()
    elapsed_seconds = end_time_total - start_time_total
    print(f"Execution time: {elapsed_seconds:.3f} seconds", file=sys.stderr)


if __name__ == "__main__":
    main()