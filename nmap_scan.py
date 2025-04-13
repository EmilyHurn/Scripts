#!/usr/bin/env python3
import sys
import argparse
import nmap
import re
from itertools import product

SCAN_PROFILES = {
    'light': '-T4 -F --max-retries 1',
    'normal': '-T4 -sV --version-intensity 5',
    'aggressive': '-A -T4',
    'intense': '-T4 -sV --version-intensity 9',
    'full': '-p- -A -T4'
}

def expand_ip_pattern(ip_pattern):
    """Expand IP patterns like:
    192.168.1.10
    192.168.[1-9].10
    192.168.1.[12,34,157]
    192.168.[4,6].[10-190]
    """
    segments = ip_pattern.split('.')
    expanded_segments = []
    
    for segment in segments:
        # Handle bracket notation
        if '[' in segment and ']' in segment:
            content = segment[segment.index('[')+1:segment.index(']')]
            parts = []
            
            # Handle comma-separated items
            for item in content.split(','):
                item = item.strip()
                # Handle range (e.g., 1-9)
                if '-' in item:
                    start, end = map(int, item.split('-'))
                    parts.extend(range(start, end+1))
                else:
                    parts.append(int(item))
            expanded_segments.append([str(x) for x in parts])
        else:
            expanded_segments.append([segment])
    
    # Generate all combinations
    ips = []
    for combination in product(*expanded_segments):
        ips.append('.'.join(combination))
    
    return ips

def scan_host(nm, ip, scan_args):
    try:
        nm.scan(ip, arguments=scan_args)
        
        if ip not in nm.all_hosts() or nm[ip].state() != 'up':
            return None
        
        results = {
            'ip': ip,
            'os': "Unknown",
            'services': [],
            'ports': []
        }
        
        if 'osmatch' in nm[ip]:
            results['os'] = nm[ip]['osmatch'][0]['name'] if nm[ip]['osmatch'] else "Unknown"
        
        for proto in nm[ip].all_protocols():
            for port, service in nm[ip][proto].items():
                if service['state'] == 'open':
                    results['ports'].append({
                        'port': port,
                        'service': service['name'],
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                        'extrainfo': service.get('extrainfo', '')
                    })
                    results['services'].append(service['name'])
        
        return results
        
    except Exception as e:
        print(f"\n[!] Error scanning {ip}: {str(e)}", file=sys.stderr)
        return None

def print_results(scan_data):
    for host in filter(None, scan_data):
        print(f"\n{host['ip']}")
        print(f"OS: {host['os']}")
        print(f"Services: {', '.join(set(host['services'])) or 'None'}")
        
        print("Open Ports:")
        for port in sorted(host['ports'], key=lambda x: x['port']):
            service_info = f"{port['service']}"
            if port['product']:
                service_info += f" ({port['product']}"
                if port['version']:
                    service_info += f" {port['version']}"
                service_info += ")"
            if port['extrainfo']:
                service_info += f" [{port['extrainfo']}]"
            print(f"    {port['port']}/tcp: {service_info}")

def main():
    parser = argparse.ArgumentParser(description='Enhanced Network Scanner with IP range support')
    parser.add_argument('targets', nargs='+', 
                      help='IP address(es) to scan. Can be single IP, comma-separated list, or range patterns like 192.168.[1-9].[10,20,30]')
    
    scan_group = parser.add_mutually_exclusive_group()
    scan_group.add_argument('-A', '--aggressive', action='store_true', 
                          help='Aggressive scan (-A)')
    scan_group.add_argument('-p', '--profile', choices=SCAN_PROFILES.keys(),
                          default='normal', help='Scan profile (default: normal)')
    scan_group.add_argument('-i', '--intensity', type=int, choices=range(0, 10),
                          help='Service detection intensity (0-9)')
    
    parser.add_argument('--timeout', type=int, default=5, 
                      help='Host timeout in minutes (default: 5)')
    args = parser.parse_args()
    
    # Build scan arguments
    if args.aggressive:
        scan_args = SCAN_PROFILES['aggressive']
    elif args.intensity is not None:
        scan_args = f"-T4 -sV --version-intensity {args.intensity}"
    else:
        scan_args = SCAN_PROFILES[args.profile]
    
    scan_args += f" --host-timeout {args.timeout}m"
    
    # Expand all target patterns
    targets = []
    for pattern in args.targets:
        if any(c in pattern for c in ['[', ',', '-']):
            targets.extend(expand_ip_pattern(pattern))
        else:
            targets.append(pattern)
    
    # Remove duplicates and sort
    targets = sorted(list(set(targets)))
    
    print(f"\nScan Configuration:")
    print(f"Targets: {', '.join(targets)}")
    print(f"Scan Type: {scan_args}")
    print(f"Timeout: {args.timeout} minutes per host\n")
    
    nm = nmap.PortScanner()
    scan_data = []
    
    try:
        for ip in targets:
            print(f"Scanning {ip}...", end=' ', flush=True)
            result = scan_host(nm, ip, scan_args)
            scan_data.append(result)
            print("✓" if result else "✗")
        
        print("\n=== Scan Results ===")
        print_results(scan_data)
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        print("\nPartial Results:")
        print_results(scan_data)
        sys.exit(1)

if __name__ == "__main__":
    main()