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
from traffic_analyzer import TrafficAnalyzer

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
