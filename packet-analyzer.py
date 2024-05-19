from scapy.all import IP, Ether
import psutil
from colorama import init, Fore, Style

def analyze_packet(packet):
    global frame_number
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        size = packet[IP].len
        ether_type = packet[Ether].type
        frame_len = len(packet)

        frame_number += 1

        print(f"{Fore.CYAN}Source IP: {src_ip} --> Destination IP: {dst_ip}")
        print(f"{Fore.YELLOW}Protocol: {proto}   Size: {size} bytes")
        print(f"{Fore.GREEN}Ether Type: {ether_type}   Frame Number: {frame_number}   Frame Length: {frame_len} bytes")
        print("-" * 50)

def select_network_interface():
    interfaces = psutil.net_if_addrs()
    print(f"{Fore.MAGENTA}Available network interfaces:")
    for interface_name, _ in interfaces.items():
        print(interface_name)
    while True:
        selected_interface = input(f"{Fore.YELLOW}Enter the name of the network interface you want to capture traffic on: ")
        if selected_interface in interfaces:
            return selected_interface
        print(f"{Fore.RED}Invalid interface name. Please try again.\n")

def traffic_analyzer(interface, packet_count):
    packets = sniff(iface=interface, prn=analyze_packet, count=packet_count)
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


    save_packets = input(f"\n{Fore.YELLOW}Do you want to save the captured packets? (yes/no): ").lower()
    if save_packets == 'yes':
        output_file = input(f"{Fore.YELLOW}Enter the output file name for the captured packets (without extension): ")
        output_file += ".pcap"
        wrpcap(output_file, packets)
        print(f"\n{Fore.CYAN}Captured packets saved to {output_file}")


if __name__ == "__main__":
    selected_interface = select_network_interface()

    while True:
        try:
            packet_count = int(input(f"{Fore.YELLOW}Enter the number of packets to capture: "))
            break
        except ValueError:
            print(f"{Fore.RED}Invalid input. Please enter a valid number.\n")

    print(f"{Fore.BLUE}Analyzing traffic on {selected_interface}...")
    traffic_analyzer(selected_interface, packet_count)