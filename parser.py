import re
from datetime import datetime
from models import LogEntry

# The Pattern bellow is made in a way that we trust the log file does not
# contain wrong ips or any of the other stuff
TRUST_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) '                 # IP
    r'\S+ \S+ '                      # Ignore identity and user
    r'\[(?P<timestamp>[^\]]+)\] '    # Timestamp
    r'"(?P<method>\S+) '             # HTTP method
    r'(?P<path>\S+) '                # Path
    r'(?P<protocol>[^"]+)" '         # Protocol
    r'(?P<status>\d{3}) '            # Status code
    r'(?P<size>\S+) '                # Response size
    r'"[^"]*" '                      # Ignore Referer
    r'"(?P<user_agent>[^"]*)"'       # User-Agent
)

# The Patter Bellow is Made with zero trust in the log format 
# (the IP address only recognizes IPv4)
FULL_LOG_PATTERN = re.compile(
    r'^(?P<ip>(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)) '
    r'(?P<ident>[^ ]+) '
    r'(?P<user>[^ ]+) '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)) '
    r'(?P<path>/[^\s]*) '
    r'(?P<protocol>HTTP/(?:1\.[01]|2(?:\.0)?|3))" '
    r'(?P<status>[1-5][0-9]{2}) '
    r'(?P<size>\d+|-)(?: '
    r'"(?P<referrer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
    r')?$'
)

LOG_PATTERN = TRUST_LOG_PATTERN


def parse_timestamp(timestamp_str):
    """
    Convert an Apache log timestamp into a datetime object.

    Example:
        "01/Jun/2026:09:14:22 +0000"
    """
    return datetime.strptime(
        timestamp_str,
        "%d/%b/%Y:%H:%M:%S %z"
    )

def parse_line(line):
    """
    Parse one Apache Combined Log Format line.

    Returns:
        LogEntry if successful
        None if the line is malformed
    """

    match = LOG_PATTERN.match(line)

    if match is None:
        return None

    try:
        data = match.groupdict()

        # Convert timestamp
        timestamp = parse_timestamp(data["timestamp"])

        # Convert status code
        status = int(data["status"])

        # Convert response size 
        # (from self research the size may not be logged in some cases so we consider "-")
        size = 0 if data["size"] == "-" else int(data["size"])

        return LogEntry(
            ip=data["ip"],
            timestamp=timestamp,
            method=data["method"],
            path=data["path"],
            protocol=data["protocol"],
            status=status,
            size=size,
            user_agent=data["user_agent"]
        )

    except Exception:
        # Any conversion failure means this line is malformed
        return None
    

