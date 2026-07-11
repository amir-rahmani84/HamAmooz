# Configuration constants for log analyzer

# Valid report sections
VALID_SECTIONS = {'basic', 'endpoints', 'hourly', 'suspicious', 'error-spikes'}

# Valid suspicious activity types
VALID_SUSPICIOUS = {'brute_force', 'high_volume', 'high_error_rate', 'endpoint_scanning'}

# Default values for CLI options
DEFAULT_SECTIONS_STRING = "basic,endpoints,hourly"
DEFAULT_SUSPICIOUS_STRING = "brute_force"
DEFAULT_TOP_N = 10

# Suspicious detection thresholds
FAILED_LOGIN_THRESHOLD = 5
ERROR_RATE_THRESHOLD = 0.8
SCANNING_ENDPOINT_THRESHOLD = 40