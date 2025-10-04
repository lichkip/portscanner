import socket
import sys
from datetime import datetime
import concurrent.futures
import argparse

def scan_port(host, port, timeout=2):
    """
    Scan a single port on the target host.
    Returns the port number if open, None otherwise.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            return port
        return None
    except socket.gaierror:
        print(f"Hostname could not be resolved: {host}")
        return None
    except socket.error:
        return None

def get_service_name(port):
    """Get common service name for a port."""
    common_ports = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
        143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
        587: "SMTP-Submission", 993: "IMAPS", 995: "POP3S",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 
        5900: "VNC", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
        8443: "HTTPS-Alt", 8888: "HTTP-Alt"
    }
    return common_ports.get(port, "Unknown")

def scan_ports(host, port_list=None, timeout=2, max_workers=50):
    """
    Scan a list of ports on the target host using multithreading.
    """
    # Default to common web server ports if none specified
    if port_list is None:
        port_list = [80, 443, 8000, 8080, 8443, 8888, 3000, 5000]
    
    print(f"\n{'='*60}")
    print(f"Starting scan on host: {host}")
    print(f"Time started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Scanning {len(port_list)} ports")
    print(f"{'='*60}\n")
    
    open_ports = []
    
    try:
        # Resolve hostname to IP
        target_ip = socket.gethostbyname(host)
        print(f"Resolved {host} to {target_ip}\n")
        
        # Use ThreadPoolExecutor for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {
                executor.submit(scan_port, target_ip, port, timeout): port 
                for port in port_list
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    service = get_service_name(result)
                    print(f"Port {result:5d} is OPEN  - {service}")
                    open_ports.append(result)
        
        print(f"\n{'='*60}")
        print(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Found {len(open_ports)} open port(s)")
        if open_ports:
            print(f"Open ports: {sorted(open_ports)}")
        print(f"{'='*60}\n")
        
        return open_ports
        
    except socket.gaierror:
        print(f"\nError: Hostname '{host}' could not be resolved.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
        description="Simple TCP Port Scanner for Web Servers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py example.com
  python port_scanner.py example.com --web
  python port_scanner.py example.com -p 80 443 8080
  python port_scanner.py example.com -r 1 1024
  python port_scanner.py example.com --common
        """
    )
    
    parser.add_argument("host", help="Target hostname or IP address")
    
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument("-p", "--ports", type=int, nargs='+',
                           help="Specific ports to scan (e.g., -p 80 443 8080)")
    port_group.add_argument("-r", "--range", type=int, nargs=2, metavar=('START', 'END'),
                           help="Port range to scan (e.g., -r 1 1024)")
    port_group.add_argument("--web", action="store_true",
                           help="Scan common web server ports (default)")
    port_group.add_argument("--common", action="store_true",
                           help="Scan top 20 most common ports")
    
    parser.add_argument("-t", "--timeout", type=float, default=2.0,
                       help="Connection timeout in seconds (default: 2.0)")
    parser.add_argument("-w", "--workers", type=int, default=50,
                       help="Max concurrent workers (default: 50)")
    
    args = parser.parse_args()
    
    # Determine which ports to scan
    if args.ports:
        port_list = args.ports
    elif args.range:
        start, end = args.range
        if start < 1 or end > 65535 or start > end:
            print("Error: Invalid port range. Ports must be between 1-65535.")
            sys.exit(1)
        port_list = list(range(start, end + 1))
    elif args.common:
        # Top 20 most commonly used ports
        port_list = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 
                    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    else:
        # Default: common web ports
        port_list = [80, 443, 8000, 8080, 8443, 8888, 3000, 5000]
    
    scan_ports(args.host, port_list, args.timeout, args.workers)

if __name__ == "__main__":
    main()
