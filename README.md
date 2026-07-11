# Apache Log Analyzer

A command‑line tool to parse and analyse web server access logs in the **Apache Combined Log Format**. It processes large log files line‑by‑line, reports basic statistics, hourly distribution, top endpoints, and detects suspicious activities (brute‑force, high volume, high error rate, endpoint scanning). Output can be plain text or JSON.

## Requirements

- Python 3.7+ (uses `statistics`, `dataclasses`, `argparse`, `gzip` – all in the standard library)
- **No third‑party dependencies** – the entire implementation relies solely on Python’s standard library.

## Installation

Clone the repository and run directly:

```bash
git clone https://github.com/amir-rahmani84/HamAmooz.git
cd HamAmooz
```

The tool is a single Python package; no installation needed.

## Usage

```bash
python main.py <logfile> [options]
```

### Basic Example

```bash
python main.py access.log
```

This prints a basic report: total requests, unique IPs, error rate, top 10 endpoints, and hourly distribution.

### Options

| Option | Description |
|--------|-------------|
| `logfile` | Path to the access log file. Supports `.gz` compressed files. |
| `--sections` | Comma‑separated list: `basic,endpoints,hourly,suspicious,error-spikes,all` (default: `basic`). |
| `--suspicious-types` | Comma‑separated list: `brute_force,high_volume,high_error_rate,endpoint_scanning,all` (default: `brute_force`). |
| `--top` | Number of top endpoints to show (default: 10). |
| `--from` | Start time (Apache log timestamp format, e.g., `01/Jun/2026:09:14:22 +0000`). |
| `--to` | End time (same format). |
| `--json` | Output report in JSON format. |
| `--output` | Write JSON report to a file. If `--json` is also given, JSON is both printed and saved. |
| `--strict-parser` | Use the **strict parser** which validates the log format and supports IPv6. The **trust parser** (default) is faster and assumes well‑formed logs. |

### Examples

1. **Full report with suspicious detection:**
   ```bash
   python main.py access.log --sections all --suspicious-types all --top 20
   ```

2. **Time‑filtered analysis:**
   ```bash
   python main.py access.log --from "01/Jun/2026:09:00:00 +0000" --to "01/Jun/2026:17:00:00 +0000"
   ```

3. **Save JSON report:**
   ```bash
   python main.py access.log --json --output report.json
   ```

4. **Use strict parser (IPv6 support):**
   ```bash
   python main.py access.log --strict-parser
   ```

## Design Decisions

- **Streaming:** The log file is read line‑by‑line using a standard `open()` loop. This ensures even multi‑gigabyte files can be processed without exhausting memory.
- **Conditional collection:** Data structures (e.g., `requests_per_ip`, `endpoints_per_ip`) are only allocated if the corresponding report section is requested. This saves time and memory.
- **Error handling:** Malformed lines are counted and skipped; the tool never crashes on bad input.
- **Suspicious activity detection:** Uses statistical thresholds (mean + 2×standard deviation) where possible, making them adaptive to the log’s traffic patterns. Thresholds are configurable via a `config` dict (currently hard‑coded).
- **Compressed files:** Files ending with `.gz` are automatically decompressed using `gzip.open`.
- **No external libraries:** The tool is built entirely with Python’s standard library, making it portable and dependency‑free. This decision aligns with the requirement to avoid third‑party parsers; the log parsing is implemented manually with regular expressions.
- **Parser modes:** Two parsers are available:
  - **Trust parser (default):** Fast, assumes the log is well‑formed. IP addresses are captured as non‑whitespace strings with no validation.
  - **Strict parser:** Slower, validates the entire log format, including IP addresses (supports both IPv4 and IPv6). Use this when you need to ensure data integrity or when IPv6 addresses are present.

## Challenges and Solutions

**Challenge:** Implementing time‑range filtering efficiently without loading the entire log into memory.

**Solution:** The `process_file()` function applies the `start_time` and `end_time` filters during streaming. Each parsed entry’s timestamp is compared against the provided bounds, and only entries that fall within the range are counted. This keeps memory usage constant (O(1)) regardless of file size, because we never store all log entries.

**Challenge:** Balancing memory usage when detecting endpoint scanning (which requires storing a set of distinct endpoints per IP).

**Solution:** The `endpoints_per_ip` structure is a `defaultdict(set)` that stores the unique endpoints accessed by each IP. This can become large, but it is only allocated when the `endpoint_scanning` suspicious type is requested. Even then, we prune the data during detection; the set size is limited by the number of distinct endpoints per IP, which is typically much smaller than the total number of requests. For extremely high‑traffic logs, one could further limit the set by capping the number of endpoints tracked per IP, but we chose to keep it simple and let the user decide whether to enable this detection.

**Challenge:** Supporting both IPv4 and IPv6 addresses without relying on external libraries.

**Solution:** The strict parser includes a comprehensive regular expression that matches all common IPv6 notations (including compressed forms). The trust parser uses a simpler `\S+` for maximum speed.

## Known Issues / Limitations

- **IPv6:** The strict parser fully supports IPv6; the trust parser does not validate IP format but still captures the address as a string.
- **Memory:** The detection of endpoint scanning stores a set of distinct endpoints per IP. For logs with millions of unique IPs and many endpoints per IP, this can consume significant memory. The set is pruned only when the detection runs; you can reduce memory by applying a threshold at collection time.
- **Error spike threshold:** The spike detection uses a dynamic threshold based on the mean and standard deviation of hourly error rates. If the log has very few hours (e.g., only one), the threshold may be unreliable.

## Testing

Not completed Yet

## Contributing

Feel free to open issues or pull requests.