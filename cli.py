import argparse
import os  # not needed but might be used later


def parse_arguments():
    """
    Parse command-line arguments.
    """

    parser = argparse.ArgumentParser(
        description="Analyze an Apache Combined Log Format access log."
    )

    # Add logfile path
    parser.add_argument(
        "logfile",
        help="Path to the log file"
    )

    # Add sections option
    parser.add_argument(
        "--sections",
        type=str,
        default="basic",
        help="Comma-separated list of report sections to include: basic,endpoints,hourly,suspicious,error-spikes,all (default: basic)"
    )

    # Add suspicious types option (only relevant if suspicious section is included)
    parser.add_argument(
        "--suspicious-types",
        type=str,
        default="brute_force",
        help="Comma-separated list of suspicious activity types: brute_force,high_volume,high_error_rate,endpoint_scanning,all (default: brute_force)"
    )

    # Add top N endpoints option
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of top endpoints to display (default: 10)"
    )

    # Add time range options
    parser.add_argument(
        "--from",
        dest="from_time",
        type=str,
        default=None,
        help="Start time for analysis (Apache log timestamp format, e.g., '01/Jun/2026:09:14:22 +0000')"
    )

    parser.add_argument(
        "--to",
        dest="to_time",
        type=str,
        default=None,
        help="End time for analysis (Apache log timestamp format)"
    )

    # Add JSON output option
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output report in JSON format instead of formatted text"
    )

    # NEW: JSON file output option
    parser.add_argument(
        "--output",
        type=str,
        help="Write JSON report to the specified file path. "
             "If --json is not given, no report is printed to stdout. "
             "If --json is also given, the JSON report is both printed and saved."
    )

    return parser.parse_args()