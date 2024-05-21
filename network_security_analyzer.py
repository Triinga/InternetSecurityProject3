import psutil
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from colorama import init
from scapy.sendrecv import sniff
from scapy.utils import wrpcap
import socket
import ipaddress
import re
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
import threading

# Initialize colorama
init(autoreset=True)

# Constants
KNOWN_MALICIOUS_IPS = ['185.192.100.93', '45.117.141.53', '201.230.222.111']
UNUSUAL_PORTS = [8080, 8443, 2222, 3389, 5900, 5060, 6666, 17185]
HIGH_FREQ_THRESHOLD = 100
BEACONING_THRESHOLD = 50

# Main analyzer class
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
        packets = sniff(iface=interface, prn=self.analyze_packet, count=packet_count)
        self.summarize_traffic(packets)

        save_packets = messagebox.askyesno("Save Packets", "Do you want to save the captured packets?")
        if save_packets:
            output_file = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
            if output_file:
                wrpcap(output_file, packets)
                messagebox.showinfo("Saved", f"Captured packets saved to {output_file}")

    def reset_analysis(self):
        self.frame_number = 0
        self.packet_counts.clear()
        self.connection_tracker.clear()
        self.suspicious_packets.clear()
        self.log_widget.config(state=tk.NORMAL)
        self.log_widget.delete('1.0', tk.END)
        self.log_widget.config(state=tk.DISABLED)

# GUI Application
class NetworkAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Analyzer Tool")
        self.create_widgets()

    def create_widgets(self):
        tab_control = ttk.Notebook(self.root)

        self.tab1 = ttk.Frame(tab_control)
        self.tab2 = ttk.Frame(tab_control)

        tab_control.add(self.tab1, text='Analyze Network Traffic')
        tab_control.add(self.tab2, text='Scan Ports')
        tab_control.pack(expand=1, fill='both')

        self.create_analyze_tab()
        self.create_port_scan_tab()

    def create_analyze_tab(self):
        frame = ttk.LabelFrame(self.tab1, text='Network Traffic Analyzer')
        frame.grid(column=0, row=0, padx=8, pady=4, sticky='nsew')

        ttk.Label(frame, text='Select Network Interface:').grid(column=0, row=0, sticky='w')
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(frame, width=20, textvariable=self.interface_var)
        self.interface_combo['values'] = list(psutil.net_if_addrs().keys())
        self.interface_combo.grid(column=1, row=0, sticky='w')
        self.interface_combo.current(0)

        ttk.Label(frame, text='Number of Packets to Capture:').grid(column=0, row=1, sticky='w')
        self.packet_count_var = tk.StringVar(value='10')
        self.packet_count_entry = ttk.Entry(frame, width=22, textvariable=self.packet_count_var)
        self.packet_count_entry.grid(column=1, row=1, sticky='w')
        self.log_text = scrolledtext.ScrolledText(frame, width=80, height=20, wrap=tk.WORD, state=tk.DISABLED)
        self.log_text.grid(column=0, row=3, columnspan=3, padx=8, pady=4)

        self.analyze_button = ttk.Button(frame, text='Start Analysis', command=self.start_analysis)
        self.analyze_button.grid(column=2, row=0, rowspan=2, padx=8, pady=4)

    def create_port_scan_tab(self):
        frame = ttk.LabelFrame(self.tab2, text='Port Scanner')
        frame.grid(column=0, row=0, padx=8, pady=4, sticky='nsew')

        ttk.Label(frame, text='Enter IP Address:').grid(column=0, row=0, sticky='w')
        self.ip_var = tk.StringVar()
        self.ip_entry = ttk.Entry(frame, width=24, textvariable=self.ip_var)
        self.ip_entry.grid(column=1, row=0, sticky='w')

        ttk.Label(frame, text='Enter Port Range:').grid(column=0, row=1, sticky='w')
        self.port_range_var = tk.StringVar(value='60-120')
        self.port_range_entry = ttk.Entry(frame, width=24, textvariable=self.port_range_var)
        self.port_range_entry.grid(column=1, row=1, sticky='w')

        self.port_log_text = scrolledtext.ScrolledText(frame, width=80, height=20, wrap=tk.WORD, state=tk.DISABLED)
        self.port_log_text.grid(column=0, row=3, columnspan=3, padx=8, pady=4)

        self.scan_button = ttk.Button(frame, text='Start Scan', command=self.start_port_scan)
        self.scan_button.grid(column=2, row=0, rowspan=2, padx=8, pady=4)

    def start_analysis(self):
        interface = self.interface_var.get()
        try:
            packet_count = int(self.packet_count_var.get())
            if packet_count <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid number of packets.")
            return

        analysis_thread = threading.Thread(target=self.run_analysis_thread, args=(interface, packet_count))
        analysis_thread.start()

    def run_analysis_thread(self, interface, packet_count):
        self.analyzer = TrafficAnalyzer(self.log_text)
        self.analyzer.run_analysis(interface, packet_count)

    def start_port_scan(self):
        ip = self.ip_var.get()
        port_range = self.port_range_var.get()
        port_range_pattern = re.compile("([0-9]+)-([0-9]+)")

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            messagebox.showerror("Invalid IP", "Please enter a valid IP address.")
            return

        port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
        if not port_range_valid:
            messagebox.showerror("Invalid Port Range", "Please enter a valid port range in format: <int>-<int> (ex: 60-120).")
            return

        port_min = int(port_range_valid.group(1))
        port_max = int(port_range_valid.group(2))

        scan_thread = threading.Thread(target=self.run_port_scan_thread, args=(ip, port_min, port_max))
        scan_thread.start()

    def run_port_scan_thread(self, ip, port_min, port_max):
        open_ports = []

        for port in range(port_min, port_max + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    s.connect((ip, port))
                    open_ports.append(port)
            except:
                pass

        self.port_log_text.config(state=tk.NORMAL)
        self.port_log_text.delete('1.0', tk.END)
        for port in open_ports:
            self.port_log_text.insert(tk.END, f"Port {port} is open on {ip}.\n")
        if not open_ports:
            self.port_log_text.insert(tk.END, "No open ports found.\n")
        self.port_log_text.config(state=tk.DISABLED)
        self.port_log_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkAnalyzerApp(root)
    root.mainloop()

