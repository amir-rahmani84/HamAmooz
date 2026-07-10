from cli import parse_arguments
from processor import process_file
from report import generate_report
from formatter import print_report

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

    # Define valid sections and suspicious types
    valid_sections = {'basic', 'endpoints', 'hourly', 'suspicious', 'error-spikes'}
    valid_suspicious = {'brute_force', 'high_volume', 'high_error_rate', 'endpoint_scanning'}

    # Parse sections and suspicious-types once, converting to sets
    sections_set = parse_list_string(args.sections, valid_sections, valid_sections)
    suspicious_set = parse_list_string(args.suspicious_types, valid_suspicious, valid_suspicious)

    # Process file with the validated sets
    stats = process_file(args.logfile, sections_set=sections_set, suspicious_set=suspicious_set)

    # Generate report with the same sets
    report = generate_report(stats, sections_set=sections_set, suspicious_set=suspicious_set)

    print_report(report)


if __name__ == "__main__":
    main()