import re
from datetime import datetime
from models import LogEntry

# ------------------------------------------------------------------
# Trust parser (fast) – assumes the log is well‑formed.
#   - IP address is captured as a sequence of non‑whitespace characters.
#   - No validation of IP format.
#   - Intended for production logs where format is known to be correct.
# ------------------------------------------------------------------
TRUST_PATTERN = re.compile(
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

# ------------------------------------------------------------------
# Strict parser (slower) – validates the log format and supports both
# IPv4 and IPv6 addresses.  Use this when you need to ensure the log
# format is correct or when you have IPv6 addresses.
# ------------------------------------------------------------------
# IPv6 regex pattern (includes all common forms)
IPV6_PATTERN = (
    r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'          # 1:2:3:4:5:6:7:8
    r'(?:[0-9a-fA-F]{1,4}:){1,7}:|'                       # 1:: / 1:2:: (compressed)
    r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'       # 1:2:3:4:5:6:7::8? Actually this covers 1:2:3:4:5:6::7
    r'(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|'
    r'[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|'
    r':(?::[0-9a-fA-F]{1,4}){1,7}|::|'                    # :: / ::1 etc.
    r'(?:[0-9a-fA-F]{1,4}:){1,6}:'                        # ::1:2:3:4:5:6
)

# IPv4 pattern (same as before)
IPV4_PATTERN = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'

# Combined IP pattern: IPv4 or IPv6
IP_PATTERN = rf'(?P<ip>(?:{IPV4_PATTERN})|(?:{IPV6_PATTERN}))'

STRICT_PATTERN = re.compile(
    r'^' + IP_PATTERN + r' '                # IP (IPv4 or IPv6)
    r'(?P<ident>[^ ]+) '                    # identity
    r'(?P<user>[^ ]+) '                     # user
    r'\[(?P<timestamp>[^\]]+)\] '                # timestamp
    r'"(?P<method>(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)) '
    r'(?P<path>/[^\s]*) '
    r'(?P<protocol>HTTP/(?:1\.[01]|2(?:\.0)?|3))" '
    r'(?P<status>[1-5][0-9]{2}) '
    r'(?P<size>\d+|-)(?: '
    r'"(?P<referrer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
    r')?$'
)


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


def parse_line(line, strict=False):
    """
    Parse one Apache Combined Log Format line.

    Args:
        line (str): The log line to parse.
        strict (bool): If True, use the strict parser (validates format, supports IPv6).
                       If False (default), use the fast trust parser.

    Returns:
        LogEntry if successful
        None if the line is malformed
    """
    pattern = STRICT_PATTERN if strict else TRUST_PATTERN
    match = pattern.match(line)

    if match is None:
        return None

    try:
        data = match.groupdict()

        # Convert timestamp
        timestamp = parse_timestamp(data.get("timestamp"))

        # Convert status code
        status = int(data["status"])

        # Convert response size 
        # (from self research the size may not be logged in some cases so we consider "-")
        size = 0 if data["size"] == "-" else int(data["size"])

        # For strict parser, we use the 'time' group; for trust, we use 'timestamp'
        # The code above uses get to handle both.
        # However, we must ensure we have a timestamp; if not, return None.
        if timestamp is None:
            return None

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