import argparse


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

    return parser.parse_args()