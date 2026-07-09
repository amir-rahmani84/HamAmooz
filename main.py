from cli import parse_arguments
from processor import process_file
from report import generate_report
from formatter import print_report


def main():

    args = parse_arguments()

    stats = process_file(args.logfile)

    report = generate_report(stats)

    print_report(report)


if __name__ == "__main__":
    main()