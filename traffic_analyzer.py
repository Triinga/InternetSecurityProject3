import tkinter as tk
from tkinter import messagebox, filedialog
from colorama import init
from scapy.sendrecv import sniff
from scapy.utils import wrpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether


# Initialize colorama
init(autoreset=True)

# Constants
KNOWN_MALICIOUS_IPS = ['185.192.100.93', '45.117.141.53', '201.230.222.111']
UNUSUAL_PORTS = [8080, 8443, 2222, 3389, 5900, 5060, 6666, 17185]
HIGH_FREQ_THRESHOLD = 100
BEACONING_THRESHOLD = 50

class TrafficAnalyzer:
    def __init__(self, log_widget):
        self.frame_number = 0
        self.packet_counts = {}
        self.connection_tracker = {}
        self.suspicious_packets = []
        self.log_widget = log_widget

    def log(self, message):
        self.log_widget.config(state=tk.NORMAL)
        self.log_widget.insert(tk.END, message + "\n")
        self.log_widget.config(state=tk.DISABLED)
        self.log_widget.see(tk.END)

    def analyze_packet(self, packet):
        self.frame_number += 1
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            self.detect_suspicious_activity(packet, src_ip, dst_ip)
            self.log_packet_info(packet, self.frame_number)
        else:
            self.log(f"Non-IP Packet Captured:")
            self.log(f"Frame Number: {self.frame_number}   Frame Length: {len(packet)} bytes")
            self.log("-" * 50)

    def log_packet_info(self, packet, frame_number):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        size = packet[IP].len
        ether_type = packet[Ether].type
        frame_len = len(packet)

        self.log(f"Source IP: {src_ip} --> Destination IP: {dst_ip}")
        self.log(f"Protocol: {proto}   Size: {size} bytes")
        self.log(f"Ether Type: {ether_type}   Frame Number: {frame_number}   Frame Length: {frame_len} bytes")
        self.log("-" * 50)

    def detect_suspicious_activity(self, packet, src_ip, dst_ip):
        proto = packet[IP].proto
        size = packet[IP].len

        if size > 1500:
            self.suspicious_packets.append(packet)
            self.log(f"Suspicious packet detected: Large packet size ({size} bytes).")

        if src_ip in KNOWN_MALICIOUS_IPS or dst_ip in KNOWN_MALICIOUS_IPS:
            self.suspicious_packets.append(packet)
            self.log(f"Suspicious packet detected: Known malicious IP address ({src_ip} or {dst_ip}).")

        if (packet.haslayer(TCP) and (packet[TCP].sport in UNUSUAL_PORTS or packet[TCP].dport in UNUSUAL_PORTS)) or \
                (packet.haslayer(UDP) and (packet[UDP].sport in UNUSUAL_PORTS or packet[UDP].dport in UNUSUAL_PORTS)):
            self.suspicious_packets.append(packet)
            self.log(f"Suspicious packet detected: Traffic on unusual port (TCP/UDP).")

        self.packet_counts[src_ip] = self.packet_counts.get(src_ip, 0) + 1
        if self.packet_counts[src_ip] > HIGH_FREQ_THRESHOLD:
            self.suspicious_packets.append(packet)
            self.log(f"Suspicious activity detected: High frequency traffic from {src_ip}.")

        conn_key = (src_ip, dst_ip)
        self.connection_tracker[conn_key] = self.connection_tracker.get(conn_key, 0) + 1
        if self.connection_tracker[conn_key] > BEACONING_THRESHOLD:
            self.suspicious_packets.append(packet)
            self.log(f"Suspicious activity detected: Frequent connections from {src_ip} to {dst_ip}.")

    def summarize_traffic(self, packets):
        self.log(f"\nTraffic Analysis Summary:")
        self.log(f"Total Packets Captured: {len(packets)}")

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

        self.log(f"Unique Source IP Addresses: {len(unique_src_ips)}")
        self.log(f"Unique Destination IP Addresses: {len(unique_dst_ips)}")
        self.log(f"Unique Protocols: {len(unique_protocols)}")
        self.log(f"Total Size: {total_size} bytes")

        self.log(f"Suspicious Packets Detected:")
        self.log(f"Large packet size: {len([p for p in self.suspicious_packets if p.haslayer(IP) and p[IP].len > 1500])}")
        self.log(f"Known malicious IP addresses: {len([p for p in self.suspicious_packets if IP in p and (p[IP].src in KNOWN_MALICIOUS_IPS or p[IP].dst in KNOWN_MALICIOUS_IPS)])}")
        self.log(f"Traffic on unusual ports: {len([p for p in self.suspicious_packets if (p.haslayer(TCP) and (p[TCP].sport in UNUSUAL_PORTS or p[TCP].dport in UNUSUAL_PORTS)) or (p.haslayer(UDP) and (p[UDP].sport in UNUSUAL_PORTS or p[UDP].dport in UNUSUAL_PORTS))])}")
        self.log(f"High frequency traffic from single source IP: {len([src_ip for src_ip, count in self.packet_counts.items() if count > HIGH_FREQ_THRESHOLD])}")
        self.log(f"Frequent connections to the same host: {len([conn_key for conn_key, count in self.connection_tracker.items() if count > BEACONING_THRESHOLD])}")

    def run_analysis(self, interface, packet_count):
        self.reset_analysis()
        try:
            packets = sniff(iface=interface, prn=self.analyze_packet, count=packet_count)
            self.summarize_traffic(packets)

            save_packets = messagebox.askyesno("Save Packets", "Do you want to save the captured packets?")
            if save_packets:
                output_file = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
                if output_file:
                    wrpcap(output_file, packets)
                    messagebox.showinfo("Saved", f"Captured packets saved to {output_file}")
        except OSError:
            self.log("Cannot analyze traffic here. Please check the interface and try again.")

    def reset_analysis(self):
        self.frame_number = 0
        self.packet_counts.clear()
        self.connection_tracker.clear()
        self.suspicious_packets.clear()
        self.log_widget.config(state=tk.NORMAL)
        self.log_widget.delete('1.0', tk.END)
        self.log_widget.config(state=tk.DISABLED)
