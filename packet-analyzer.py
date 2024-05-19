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
