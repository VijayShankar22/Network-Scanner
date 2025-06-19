import concurrent.futures
import socket
import subprocess
import ipaddress
import platform
import os
import time
from colorama import init, Fore
from tqdm import tqdm

init()

def print_banner(banner, color=None):
    if color is not None:
        print(f"\033[{color}m{banner}\033[0m")
    else:
        print(banner)

def validate_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def validate_port(port):
    try:
        return 1 <= int(port) <= 65535
    except ValueError:
        return False

def local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        return "127.0.0.1"

def ip_range(start_ip, stop_ip):
    try:
        start_ip_obj = ipaddress.IPv4Address(start_ip)
        stop_ip_obj = ipaddress.IPv4Address(stop_ip)
        if start_ip_obj > stop_ip_obj:
            raise ValueError("Start IP must be less than or equal to stop IP")
        return [str(ipaddress.IPv4Address(ip_int)) for ip_int in range(int(start_ip_obj), int(stop_ip_obj) + 1)]
    except ipaddress.AddressValueError:
        print(Fore.RED + "Invalid IP address format" + Fore.RESET)
        return []
    except ValueError as e:
        print(Fore.RED + str(e) + Fore.RESET)
        return []


def ping_host(ip):
    ping_param = '-n' if platform.system().lower() == 'windows' else '-c'
    ping_command = ['ping', ping_param, '2', ip]
    try:
        with subprocess.Popen(
            ping_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors='ignore'
        ) as process:
            output, _ = process.communicate(timeout=5)
            # Check for successful ping replies
            if platform.system().lower() == 'windows':
                return "Reply from" in output and "Destination host unreachable" not in output
            else:
                return "bytes from" in output
    except (subprocess.SubprocessError, OSError):
        return False


def scan_ip(ip, port, timeout=0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return (ip, port) if result == 0 else None
    except Exception:
        return None


def scan_ip_range(ips, ports, max_workers=os.cpu_count() * 10):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip_port = {
            executor.submit(scan_ip, ip, port): (ip, port)
            for ip in ips for port in ports
        }
        with tqdm(total=len(ips), desc="Scanning IPs", unit="IP") as pbar:
            ip_progress = set()
            for future in concurrent.futures.as_completed(future_to_ip_port):
                ip, _ = future_to_ip_port[future]
                if ip not in ip_progress:
                    ip_progress.add(ip)
                    pbar.update(1)
                if (result := future.result()) is not None:
                    results.append(result)
    return results


def parse_ports(port_input):
    ports = []
    try:
        if port_input.lower() == 'common':
            return [20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139, 143, 161, 389, 443, 445, 465, 514, 587, 631, 993, 995, 1723, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888]

        for part in port_input.split(','):
            if '-' in part:
                start, end = part.split('-')
                if not (validate_port(start) and validate_port(end)):
                    raise ValueError("Ports must be between 1 and 65535")
                ports.extend(range(int(start), int(end) + 1))
            else:
                if not validate_port(part):
                    raise ValueError(f"Invalid port: {part}")
                ports.append(int(part))
        return ports
    except ValueError as e:
        print(Fore.RED + str(e) + Fore.RESET)
        return []


def print_results_table(results, title="Scan Results"):
    if not results:
        print(Fore.YELLOW + "No open ports found." + Fore.RESET)
        return 0
    print(f"\n{Fore.BLUE}{title}{Fore.RESET}")
    print("_____________________________________")
    print("|   IP Address    |  Port  | Status |")
    print("|_________________|________|________|")
    for ip, port in results:
        print(f"| {ip:^14}  | {port:^6} | {Fore.GREEN}Open{Fore.RESET}   |")
    print("|_________________|________|________|")
    return len(results)


def print_ping_results_table(ip_status, title="Ping Scan Results"):
    if not ip_status:
        print(Fore.YELLOW + "No hosts scanned." + Fore.RESET)
        return 0, 0
    print(f"\n{Fore.BLUE}{title}{Fore.RESET}")
    print("__________________________________")
    print("|   IP Address    |  Host Status |")
    print("|_________________|______________|")
    hosts_up = 0
    for ip, status in ip_status:
        status_text = "Up" if status else "Down"
        color = Fore.GREEN if status else Fore.RED
        print(f"| {ip:^14}  | {color}{status_text:^12}{Fore.RESET} |")
        if status:
            hosts_up += 1
    print("|_________________|______________|")
    return len(ip_status), hosts_up




def main_menu():
    while True:

        print_banner(r"""
                     
|=====================================================================================|
|    _   _      _                      _      ____                                    |
|   | \ | | ___| |___      _____  _ __| | __ / ___|  ___ __ _ _ __  _ __   ___ _ __   |
|   |  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ / \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|  |
|   | |\  |  __/ |_ \ V  V / (_) | |  |   <   ___) | (_| (_| | | | | | | |  __/ |     |
|   |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\ |____/ \___\__,_|_| |_|_| |_|\___|_|     |
|                                                                                     |  
|                                                                                     |
|                                                        - github.com/vijayshankar22  |
|=====================================================================================|

                     
""", 91)
        print(Fore.LIGHTGREEN_EX + "1. Ping scan" + Fore.RESET)
        print(Fore.LIGHTGREEN_EX + "2. Ping scan (multiple hosts)" + Fore.RESET)
        print(Fore.LIGHTGREEN_EX + "3. Scan Single IP" + Fore.RESET)
        print(Fore.LIGHTGREEN_EX + "4. Scan Range of IPs" + Fore.RESET)
        print(Fore.LIGHTGREEN_EX + "5. Scan this machine" + Fore.RESET)
        print(Fore.LIGHTGREEN_EX + "6. Scan all hosts on this subnet" + Fore.RESET)
        print(Fore.LIGHTGREEN_EX + "7. Scan full network" + Fore.RESET)
        print(Fore.LIGHTGREEN_EX + "8. Exit" + Fore.RESET)
        print("")
        
        try:
            choice = int(input("Enter a number from above (1-8): "))
            if 1 <= choice <= 8:
                if choice == 8:
                    print(Fore.BLUE + "Exiting scanner. Goodbye!" + Fore.RESET)
                    break
                process_choice(choice)
            else:
                print(Fore.RED + "Please enter a number between 1 and 8." + Fore.RESET)
        except ValueError:
            print(Fore.RED + "Invalid input. Please enter a number." + Fore.RESET)
        input("\nPress Enter to continue...")



def process_choice(choice):
    start_time = time.time()
    if choice == 1:
        while True:
            ip_1 = input("Enter host IP address: ")
            if validate_ip(ip_1):
                break
            print(Fore.RED + "Invalid IP address format." + Fore.RESET)
        ping = ping_host(ip_1)
        total_ips, hosts_up = print_ping_results_table([(ip_1, ping)], f"Ping Scan Results for {ip_1}")
        print(f"\n{Fore.BLUE}Summary:{Fore.RESET}")
        print(f"Total IPs scanned: {total_ips}")
        print(f"Hosts up: {hosts_up}")
        print(f"Time taken: {time.time() - start_time:.2f} seconds")

    elif choice == 2:
        while True:
            ip_range_2 = input("Enter IP range (e.g., 192.168.1.1-192.168.1.255): ")
            if '-' not in ip_range_2:
                print(Fore.RED + "Invalid format. Use start_ip-end_ip." + Fore.RESET)
                continue
            start_ip, stop_ip = ip_range_2.split('-')
            if validate_ip(start_ip) and validate_ip(stop_ip):
                break
            print(Fore.RED + "Invalid IP address format." + Fore.RESET)
        ips = ip_range(start_ip, stop_ip)
        if not ips:
            return
        ip_status = []
        max_workers = min(os.cpu_count() * 10, 50)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in ips}
            with tqdm(total=len(ips), desc="Pinging IPs", unit="IP") as pbar:
                for future in concurrent.futures.as_completed(futures):
                    ip_status.append((futures[future], future.result()))
                    pbar.update(1)
        total_ips, hosts_up = print_ping_results_table(ip_status, "Ping Scan Results")
        print(f"\n{Fore.BLUE}Summary:{Fore.RESET}")
        print(f"Total IPs scanned: {total_ips}")
        print(f"Hosts up: {hosts_up}")
        print(f"Time taken: {time.time() - start_time:.2f} seconds")

    elif choice == 3:
        while True:
            ip_3 = input("Enter IP to scan: ")
            if validate_ip(ip_3):
                break
            print(Fore.RED + "Invalid IP address format." + Fore.RESET)
        port_3 = input("Enter port(s) (e.g., 21,80,443 or 1-65535 or 'common' for default ports): ")
        ports = parse_ports(port_3)
        if not ports:
            return
        results = scan_ip_range([ip_3], ports)
        open_ports = print_results_table(results, f"Scan Results for {ip_3}")
        print(f"\n{Fore.BLUE}Summary:{Fore.RESET}")
        print(f"Total IPs scanned: 1")
        print(f"Open ports found: {open_ports}")
        print(f"Time taken: {time.time() - start_time:.2f} seconds")

    elif choice == 4:
        while True:
            ip_range_4 = input("Enter IP range (e.g., 192.168.1.1-192.168.1.255): ")
            if '-' not in ip_range_4:
                print(Fore.RED + "Invalid format. Use start_ip-end_ip." + Fore.RESET)
                continue
            start_ip, stop_ip = ip_range_4.split('-')
            if validate_ip(start_ip) and validate_ip(stop_ip):
                break
            print(Fore.RED + "Invalid IP address format." + Fore.RESET)
        port_4 = input("Enter port(s) (e.g., 21,80,443 or 1-65535 or 'common' for default ports): ")
        ports = parse_ports(port_4)
        if not ports:
            return
        ips = ip_range(start_ip, stop_ip)
        if not ips:
            return
        results = scan_ip_range(ips, ports)
        open_ports = print_results_table(results, "IP Range Scan Results")
        print(f"\n{Fore.BLUE}Summary:{Fore.RESET}")
        print(f"Total IPs scanned: {len(ips)}")
        print(f"Open ports found: {open_ports}")
        print(f"Time taken: {time.time() - start_time:.2f} seconds")

    elif choice == 5:
        device_ip = local_ip()
        print(f"Device IP: {device_ip}")
        port_5 = input("Enter port(s) (e.g., 21,80,443 or 1-65535 or 'common' for default ports): ")
        ports = parse_ports(port_5)
        if not ports:
            return
        results = scan_ip_range([device_ip], ports)
        open_ports = print_results_table(results, f"Scan Results for {device_ip}")
        print(f"\n{Fore.BLUE}Summary:{Fore.RESET}")
        print(f"Total IPs scanned: 1")
        print(f"Open ports found: {open_ports}")
        print(f"Time taken: {time.time() - start_time:.2f} seconds")

    elif choice == 6:
        def get_subnet(ip):
            parts = ip.split('.')
            parts[-1] = '0'
            return '.'.join(parts)
        device_ip = local_ip()
        subnet = get_subnet(device_ip)
        print(f"Scanning subnet: {subnet}/24")
        port_6 = input("Enter port(s) (e.g., 21,80,443 or 1-65535 or 'common' for default ports): ")
        ports = parse_ports(port_6)
        if not ports:
            return
        subnet_parts = subnet.split('.')
        start_ip = f"{subnet_parts[0]}.{subnet_parts[1]}.{subnet_parts[2]}.1"
        stop_ip = f"{subnet_parts[0]}.{subnet_parts[1]}.{subnet_parts[2]}.255"
        if not (validate_ip(start_ip) and validate_ip(stop_ip)):
            print(Fore.RED + "Invalid subnet range." + Fore.RESET)
            return
        ip_addresses = ip_range(start_ip, stop_ip)
        if not ip_addresses:
            return
        results = scan_ip_range(ip_addresses, ports)
        open_ports = print_results_table(results, f"Subnet Scan Results ({subnet}/24)")
        print(f"\n{Fore.BLUE}Summary:{Fore.RESET}")
        print(f"Total IPs scanned: {len(ip_addresses)}")
        print(f"Open ports found: {open_ports}")
        print(f"Time taken: {time.time() - start_time:.2f} seconds")

    elif choice == 7:
        ip_range_7 = input("Enter IP range (e.g., 192.168.1.1-192.168.255.255) or press Enter for default (172.16.0.0-172.16.255.255): ")
        if not ip_range_7:
            start_ip, stop_ip = '172.16.0.0', '172.16.255.255'
        else:
            if '-' not in ip_range_7:
                print(Fore.RED + "Invalid format. Use start_ip-end_ip." + Fore.RESET)
                return
            start_ip, stop_ip = ip_range_7.split('-')
            if not (validate_ip(start_ip) and validate_ip(stop_ip)):
                print(Fore.RED + "Invalid IP address format." + Fore.RESET)
                return
        port_7 = input("Enter port(s) (e.g., 21,80,443 or 1-65535 or 'common' for default ports): ")
        ports = parse_ports(port_7)
        if not ports:
            return
        ips = ip_range(start_ip, stop_ip)
        if not ips:
            return
        results = scan_ip_range(ips, ports)
        open_ports = print_results_table(results, "Full Network Scan Results")
        print(f"\n{Fore.BLUE}Summary:{Fore.RESET}")
        print(f"Total IPs scanned: {len(ips)}")
        print(f"Open ports found: {open_ports}")
        print(f"Time taken: {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    main_menu()
