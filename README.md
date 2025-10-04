# Python Port Scanner

A simple multithreaded TCP port scanner for network diagnostics and security auditing.

## Usage

```bash
# Scan common web ports (default)
python port_scanner.py example.com

# Scan specific ports
python port_scanner.py example.com -p 80 443 8080

# Scan port range
python port_scanner.py example.com -r 1 1024

# Scan top 20 common ports
python port_scanner.py example.com --common
```

## Options

- `-p, --ports` - Specific ports to scan
- `-r, --range` - Port range (start end)
- `--web` - Scan common web ports (default)
- `--common` - Scan top 20 common ports
- `-t, --timeout` - Connection timeout in seconds (default: 2.0)
- `-w, --workers` - Max concurrent threads (default: 50)

## Legal Notice

**Only scan systems you own or have explicit permission to scan.** Unauthorized port scanning may be illegal in your jurisdiction.

## Requirements

Python 3.6+
