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
