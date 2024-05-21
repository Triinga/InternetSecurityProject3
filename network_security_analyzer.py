import psutil
from colorama import init, Fore, Style
from scapy.sendrecv import sniff
from scapy.utils import wrpcap
import socket
import ipaddress
import re
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

# Initialize colorama
init(autoreset=True)

# Constants
KNOWN_MALICIOUS_IPS = ['192.168.1.100', '203.0.113.1']
UNUSUAL_PORTS = [8080, 8443, 2222, 3389, 5900, 5060, 6666, 17185]
HIGH_FREQ_THRESHOLD = 100
BEACONING_THRESHOLD = 50

# Utility functions
def print_packet_info(packet, frame_number):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    size = packet[IP].len
    ether_type = packet[Ether].type
    frame_len = len(packet)

    print(f"{Fore.CYAN}Source IP: {src_ip} --> Destination IP: {dst_ip}")
    print(f"{Fore.YELLOW}Protocol: {proto}   Size: {size} bytes")
    print(f"{Fore.GREEN}Ether Type: {ether_type}   Frame Number: {frame_number}   Frame Length: {frame_len} bytes")
    print("-" * 50)


# Main analyzer class
class TrafficAnalyzer:
    def __init__(self):
        self.frame_number = 0
        self.packet_counts = {}
        self.connection_tracker = {}
        self.suspicious_packets = []

    def detect_suspicious_activity(self, packet, src_ip, dst_ip):
        proto = packet[IP].proto
        size = packet[IP].len

        # Detect large packet size
        if size > 1500:
            self.suspicious_packets.append(packet)
            print(f"{Fore.RED}Suspicious packet detected: Large packet size ({size} bytes).")

        # Detect traffic to/from known malicious IP addresses
        if src_ip in KNOWN_MALICIOUS_IPS or dst_ip in KNOWN_MALICIOUS_IPS:
            self.suspicious_packets.append(packet)
            print(f"{Fore.RED}Suspicious packet detected: Known malicious IP address ({src_ip} or {dst_ip}).")

        # Detect traffic on unusual ports
        if (packet.haslayer(TCP) and (packet[TCP].sport in UNUSUAL_PORTS or packet[TCP].dport in UNUSUAL_PORTS)) or \
                (packet.haslayer(UDP) and (packet[UDP].sport in UNUSUAL_PORTS or packet[UDP].dport in UNUSUAL_PORTS)):
            self.suspicious_packets.append(packet)
            print(f"{Fore.RED}Suspicious packet detected: Traffic on unusual port (TCP/UDP).")

        # Track and detect high-frequency traffic from a single source IP
        self.packet_counts[src_ip] = self.packet_counts.get(src_ip, 0) + 1
        if self.packet_counts[src_ip] > HIGH_FREQ_THRESHOLD:
            self.suspicious_packets.append(packet)
            print(f"{Fore.RED}Suspicious activity detected: High frequency traffic from {src_ip}.")

        # Detect frequent connections to the same host (beaconing behavior)
        conn_key = (src_ip, dst_ip)
        self.connection_tracker[conn_key] = self.connection_tracker.get(conn_key, 0) + 1
        if self.connection_tracker[conn_key] > BEACONING_THRESHOLD:
            self.suspicious_packets.append(packet)
            print(f"{Fore.RED}Suspicious activity detected: Frequent connections from {src_ip} to {dst_ip}.")

    def summarize_traffic(self, packets):
        print(f"\n{Fore.CYAN}Traffic Analysis Summary:")
        print(f"{Fore.CYAN}Total Packets Captured: {Fore.GREEN}{len(packets)}")

        unique_src_ips = set()
        unique_dst_ips = set()
        unique_protocols = set()
        total_size = 0

        for packet in packets:
            if IP in packet:
                unique_src_ips.add(packet[IP].src)
                unique_dst_ips.add(packet[IP].dst)
                unique_protocols.add(packet[IP].proto)
                total_size += packet[IP].len

        print(f"{Fore.WHITE}Unique Source IP Addresses: {Fore.GREEN}{len(unique_src_ips)}")
        print(f"{Fore.WHITE}Unique Destination IP Addresses: {Fore.GREEN}{len(unique_dst_ips)}")
        print(f"{Fore.WHITE}Unique Protocols: {Fore.GREEN}{len(unique_protocols)}")
        print(f"{Fore.WHITE}Total Size: {Fore.GREEN}{total_size} bytes")

        # Print count of suspicious packets detected for each type of detection
        print(f"{Fore.CYAN}Suspicious Packets Detected:")
        print(f"{Fore.RED}Large packet size: {len([p for p in self.suspicious_packets if p.haslayer(IP) and p[IP].len > 1500])}")
        print(f"{Fore.RED}Known malicious IP addresses: {len([p for p in self.suspicious_packets if IP in p and (p[IP].src in KNOWN_MALICIOUS_IPS or p[IP].dst in KNOWN_MALICIOUS_IPS)])}")
        print(f"{Fore.RED}Traffic on unusual ports: {len([p for p in self.suspicious_packets if (p.haslayer(TCP) and (p[TCP].sport in UNUSUAL_PORTS or p[TCP].dport in UNUSUAL_PORTS)) or (p.haslayer(UDP) and (p[UDP].sport in UNUSUAL_PORTS or p[UDP].dport in UNUSUAL_PORTS))])}")
        print(f"{Fore.RED}High frequency traffic from single source IP: {len([src_ip for src_ip, count in self.packet_counts.items() if count > HIGH_FREQ_THRESHOLD])}")
        print(f"{Fore.RED}Frequent connections to the same host: {len([conn_key for conn_key, count in self.connection_tracker.items() if count > BEACONING_THRESHOLD])}")

    def run_analysis(self, interface, packet_count):
        self.suspicious_packets = []
        packets = sniff(iface=interface, prn=self.analyze_packet, count=packet_count)
        self.summarize_traffic(packets)

        save_packets = input(f"\n{Fore.YELLOW}Do you want to save the captured packets? (yes/no): ").lower()
        if save_packets == 'yes':
            output_file = input(f"{Fore.YELLOW}Enter the output file name for the captured packets (without extension): ")
            output_file += ".pcap"
            wrpcap(output_file, packets)
            print(f"\n{Fore.CYAN}Captured packets saved to {output_file}")

# Helper functions
def select_network_interface():
    interfaces = psutil.net_if_addrs()
    print(f"{Fore.MAGENTA}Available network interfaces:")
    for interface_name in interfaces.keys():
        print(interface_name)
    while True:
        selected_interface = input(f"{Fore.YELLOW}Enter the name of the network interface you want to capture traffic on: ")
        if selected_interface in interfaces:
            return selected_interface
        print(f"{Fore.RED}Invalid interface name. Please try again.\n")


def port_scanner():
    port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
    port_min = 0
    port_max = 65535

    print("===========================Port Scanner==============================")

    open_ports = []
    while True:
        ip_add_entered = input("\nPlease enter the IP address that you want to scan: ")
        try:
            ip_address_obj = ipaddress.ip_address(ip_add_entered)
            print("You entered a valid IP address.")
            break
        except ValueError:
            print("You entered an invalid IP address")

    while True:
        print("Please enter the range of ports you want to scan in format: <int>-<int> (ex: 60-120)")
        port_range = input("Enter port range: ")
        port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
        if port_range_valid:
            port_min = int(port_range_valid.group(1))
            port_max = int(port_range_valid.group(2))
            break

    for port in range(port_min, port_max + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect((ip_add_entered, port))
                open_ports.append(port)
        except:
            pass

    for port in open_ports:
        print(f"Port {port} is open on {ip_add_entered}.")

def main():
    print(f"{Fore.BLUE}Welcome to the Network Utility Tool")
    print(f"1. Analyze Network Traffic")
    print(f"2. Scan Ports")

    while True:
        choice = input(f"{Fore.YELLOW}Enter your choice (1 or 2): ")
        if choice in ['1', '2']:
            break
        else:
            print(f"{Fore.RED}Invalid choice. Please enter 1 or 2.\n")

    if choice == '1':
        selected_interface = select_network_interface()
        while True:
            try:
                packet_count = int(input(f"{Fore.YELLOW}Enter the number of packets to capture: "))
                if packet_count > 0:
                    break
                else:
                    print(f"{Fore.RED}Invalid input. Please enter a positive number.\n")
                break
            except ValueError:
                print(f"{Fore.RED}Invalid input. Please enter a valid number.\n")
        print(f"{Fore.BLUE}Analyzing traffic on {selected_interface}...")
        analyzer = TrafficAnalyzer()
        # traffic_analyzer(selected_interface, packet_count)
    else:
        port_scanner()

if __name__ == "__main__":
    main()
