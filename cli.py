import argparse


def parse_arguments():
    """
    Parse command-line arguments.
    """

    parser = argparse.ArgumentParser(
        description="Analyze an Apache Combined Log Format access log."
    )

    # for the basic needs of the task we only need the logfile path
    parser.add_argument(
        "logfile",
        help="Path to the log file"
    )

    return parser.parse_args()