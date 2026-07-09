"""
Dashboard Module.

Provides the graphical user interface (GUI) for the SOC Console,
allowing real-time monitoring of network traffic and security alerts.
"""
import os
import sys
from datetime import datetime
from collections import Counter
from typing import Any, Dict

# Ensure parent directory is on sys.path for module imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import customtkinter as ctk
from tkinter import ttk, messagebox
from packet_sniffer import PacketSniffer
from arp_detector import ARPDetector
from logger_manager import log_packet, log_alert
from report_generator import generate_csv_report, generate_alerts_report
import threading

SIDEBAR_WIDTH = 220
button_cfg = {"width": SIDEBAR_WIDTH - 40, "height": 36}
# Ensure the GUI package works even if running from a different cwd
BASE_DIR = os.path.dirname(__file__)

class Dashboard:
    def __init__(self):
        # Configure overall appearance before creating any widget
        ctk.set_appearance_mode("dark")  # dark theme
        ctk.set_default_color_theme("dark-blue")  # a sleek cyber‑blue palette

        self.root = ctk.CTk()
        self.root.title("SOC Console – Advanced Packet Sniffer")
        self.root.resizable(True, True)
        self.root.minsize(1000, 600)
        
        # -----------------------------------------------------------------
        # Auto‑fit to the display size
        # -----------------------------------------------------------------
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        if screen_w >= 1600:
            try:
                self.root.state("zoomed")
            except Exception:
                self.root.geometry(f"{screen_w - 20}x{screen_h - 20}")
        else:
            margin_w = int(screen_w * 0.05)   # 5% width margin
            margin_h = int(screen_h * 0.07)   # 7% height margin
            self.root.geometry(f"{screen_w - margin_w}x{screen_h - margin_h}")

        # Backend objects
        self.sniffer = None
        self.detector = ARPDetector()
        
        # Thread‑safe storage for UI
        self.lock = threading.Lock()
        self.packets = []          # list of dicts (all captured)
        self.alerts = []           # list of alert dicts
        
        self.tcp_cnt = 0
        self.udp_cnt = 0
        self.icmp_cnt = 0
        self.total_cnt = 0
        self.arp_alert_cnt = 0
        
        # Threat intelligence counters
        self.src_ip_counter = Counter()
        self.dst_ip_counter = Counter()
        
        # Active protocol filters
        self.active_protocols = {"TCP", "UDP", "ICMP", "ARP", "IPv6", "OTHER"}

        # ----- Root grid layout: top header (spans) | middle (sidebar | main) | bottom footer (spans) -----
        self.root.columnconfigure(0, weight=0, minsize=SIDEBAR_WIDTH)
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=0)
        self.root.rowconfigure(1, weight=1)
        self.root.rowconfigure(2, weight=0)

        # ----- Top Header (spans) -----
        self._build_header()

        # ----- Sidebar (fixed width, column 0) -----
        self.sidebar = ctk.CTkFrame(self.root, width=SIDEBAR_WIDTH, corner_radius=0, fg_color="#1a1a1a")
        self.sidebar.grid(row=1, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self._build_sidebar()

        # ----- Main Content (column 1, stretches) -----
        self.main_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.main_frame.grid(row=1, column=1, sticky="nsew", padx=15, pady=15)
        
        # Main frame internal grid: 
        # row 0=main_header, row 1=cards, row 2=live alerts, row 3=table(expand), row 4=bottom panels
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(0, weight=0)
        self.main_frame.rowconfigure(1, weight=0)
        self.main_frame.rowconfigure(2, weight=0)
        self.main_frame.rowconfigure(3, weight=3)
        self.main_frame.rowconfigure(4, weight=2)

        self._build_main_header()
        self._build_dashboard()
        self._build_live_alerts()
        self._build_table()
        self._build_bottom_panels()
        self._build_footer()
        
        self._update_clock()
        self._periodic_talkers_update()

    # ---------------------------------------------------------------------
    # Header UI
    # ---------------------------------------------------------------------
    def _build_header(self):
        self.header_frame = ctk.CTkFrame(self.root, fg_color="#242424", corner_radius=0)
        self.header_frame.grid(row=0, column=0, columnspan=2, sticky="ew", ipadx=10, ipady=10)
        
        self.header_frame.columnconfigure(0, weight=1)
        self.header_frame.columnconfigure(1, weight=0)
        self.header_frame.columnconfigure(2, weight=0)
        
        # Left side - Logo Title
        logo_lbl = ctk.CTkLabel(self.header_frame, text="SOC CONSOLE - Advanced Packet Sniffer", font=("Helvetica", 18, "bold"), text_color="#ffffff")
        logo_lbl.grid(row=0, column=0, sticky="w", padx=(20, 40))
        
        self.lbl_time = ctk.CTkLabel(self.header_frame, text="Current Time: --:--:--", font=("Courier", 14), text_color="#aaaaaa")
        self.lbl_time.grid(row=0, column=1, sticky="e", padx=(0, 20))
        
        lbl_interface = ctk.CTkLabel(self.header_frame, text="Interface: Default", font=("Helvetica", 14), text_color="#aaaaaa")
        lbl_interface.grid(row=0, column=2, sticky="e", padx=(0, 20))

    def _build_main_header(self):
        self.main_header_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.main_header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        
        self.main_header_frame.columnconfigure(0, weight=1)
        self.main_header_frame.columnconfigure(1, weight=0)
        
        # Left side - Titles & Status
        left_frame = ctk.CTkFrame(self.main_header_frame, fg_color="transparent")
        left_frame.grid(row=0, column=0, sticky="w")
        
        lbl_title = ctk.CTkLabel(left_frame, text="Advanced Packet Sniffer & ARP Threat Detection System", 
                                 font=("Helvetica", 16, "bold"), text_color="#ffffff")
        lbl_title.pack(anchor="w", pady=(0,0))
        
        status_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        status_frame.pack(anchor="w", pady=(2,0))
        
        ctk.CTkLabel(status_frame, text="● Monitoring : ", font=("Helvetica", 12, "bold"), text_color="#aaaaaa").pack(side="left")
        ctk.CTkLabel(status_frame, text="ONLINE", font=("Helvetica", 12, "bold"), text_color="#00ff88").pack(side="left", padx=(0, 20))
        
        ctk.CTkLabel(status_frame, text="● Capture : ", font=("Helvetica", 12, "bold"), text_color="#aaaaaa").pack(side="left")
        self.lbl_status = ctk.CTkLabel(status_frame, text="READY", font=("Helvetica", 12, "bold"), text_color="#ffcc00")
        self.lbl_status.pack(side="left")
        
        # Right side - Total Captured
        self.lbl_live_counter = ctk.CTkLabel(self.main_header_frame, text="Total Captured : 0", font=("Helvetica", 12, "bold"), text_color="#ffffff")
        self.lbl_live_counter.grid(row=0, column=1, sticky="e", padx=10)

    def _update_clock(self):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.lbl_time.configure(text=f"Current Time: {current_time}")
        self.root.after(1000, self._update_clock)

    def _periodic_talkers_update(self):
        self._update_top_talkers()
        self.root.after(2000, self._periodic_talkers_update)

    # ---------------------------------------------------------------------
    # Sidebar UI
    # ---------------------------------------------------------------------
    def _build_sidebar(self):
        lbl_sidebar_logo = ctk.CTkLabel(self.sidebar, text="SOC CONSOLE", font=("Helvetica", 18, "bold"), text_color="#00ccff")
        lbl_sidebar_logo.pack(anchor="center", pady=(15, 5))

        # --- FILTERS SECTION ---
        lbl_filters = ctk.CTkLabel(self.sidebar, text="TRAFFIC FILTERS", font=("Helvetica", 12, "bold"), text_color="#aaaaaa")
        lbl_filters.pack(anchor="w", padx=20, pady=(10, 5))
        
        self.filter_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.filter_frame.pack(fill="x", padx=25)
        
        self.var_tcp = ctk.IntVar(value=1)
        self.var_udp = ctk.IntVar(value=1)
        self.var_icmp = ctk.IntVar(value=1)
        self.var_arp = ctk.IntVar(value=1)
        self.var_ipv6 = ctk.IntVar(value=1)
        self.var_other = ctk.IntVar(value=1)
        
        chk_opts = {"font": ("Helvetica", 13), "command": self._update_filters}
        self.chk_tcp = ctk.CTkCheckBox(self.filter_frame, text="TCP", variable=self.var_tcp, **chk_opts)
        self.chk_udp = ctk.CTkCheckBox(self.filter_frame, text="UDP", variable=self.var_udp, **chk_opts)
        self.chk_icmp = ctk.CTkCheckBox(self.filter_frame, text="ICMP", variable=self.var_icmp, **chk_opts)
        self.chk_arp = ctk.CTkCheckBox(self.filter_frame, text="ARP", variable=self.var_arp, **chk_opts)
        self.chk_ipv6 = ctk.CTkCheckBox(self.filter_frame, text="IPv6", variable=self.var_ipv6, **chk_opts)
        self.chk_other = ctk.CTkCheckBox(self.filter_frame, text="Other", variable=self.var_other, **chk_opts)
        
        self.chk_tcp.pack(anchor="w", pady=2)
        self.chk_udp.pack(anchor="w", pady=2)
        self.chk_icmp.pack(anchor="w", pady=2)
        self.chk_arp.pack(anchor="w", pady=2)
        self.chk_ipv6.pack(anchor="w", pady=2)
        self.chk_other.pack(anchor="w", pady=2)

        # --- SEARCH SECTION ---
        lbl_search = ctk.CTkLabel(self.sidebar, text="SEARCH", font=("Helvetica", 12, "bold"), text_color="#aaaaaa")
        lbl_search.pack(anchor="w", padx=20, pady=(15, 5))
        
        self.search_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.search_frame.pack(fill="x", padx=15)
        
        self.search_var = ctk.StringVar()
        self.entry_search = ctk.CTkEntry(self.search_frame, placeholder_text="IP or Protocol...", textvariable=self.search_var)
        self.entry_search.pack(fill="x", pady=(0, 10))
        self.entry_search.bind("<KeyRelease>", lambda e: self._search_packets())
        
        self.btn_clear_search = ctk.CTkButton(self.search_frame, text="Clear Search", height=30,
                                               fg_color="#333333", hover_color="#444444", text_color="#cccccc",
                                               command=self._clear_search)
        self.btn_clear_search.pack(fill="x")
        
        # --- CONTROLS SECTION ---
        lbl_controls = ctk.CTkLabel(self.sidebar, text="CONTROLS", font=("Helvetica", 12, "bold"), text_color="#aaaaaa")
        lbl_controls.pack(anchor="w", padx=20, pady=(15, 5))

        self.btn_start = ctk.CTkButton(self.sidebar, text="Start Sniffing", fg_color="#2b5c8f", hover_color="#3673b3",
                                       font=("Helvetica", 14, "bold"), command=self.start_sniffing, **button_cfg)
        self.btn_start.pack(pady=5, padx=20)

        self.btn_stop = ctk.CTkButton(self.sidebar, text="Stop Sniffing", fg_color="#333333", hover_color="#C0392B",
                                      font=("Helvetica", 14, "bold"), state="disabled", command=self.stop_sniffing, **button_cfg)
        self.btn_stop.pack(pady=5, padx=20)

        self.btn_export = ctk.CTkButton(self.sidebar, text="Export CSV Report", fg_color="#2980B9", hover_color="#3498DB",
                                        command=self.export_report, **button_cfg)
        self.btn_export.pack(pady=5, padx=20)

        self.btn_export_alerts = ctk.CTkButton(self.sidebar, text="Export Alerts", fg_color="#8E44AD", hover_color="#9B59B6",
                                               command=self.export_alerts, **button_cfg)
        self.btn_export_alerts.pack(pady=5, padx=20)

        self.btn_test_arp = ctk.CTkButton(self.sidebar, text="Test ARP Detection", fg_color="#D35400", hover_color="#E67E22",
                                          command=self.run_arp_test, **button_cfg)
        self.btn_test_arp.pack(pady=5, padx=20)

        # Bottom exit
        self.btn_exit = ctk.CTkButton(self.sidebar, text="Exit Console", fg_color="transparent", border_width=1, border_color="#555555",
                                      command=self._on_exit, **button_cfg)
        self.btn_exit.pack(side="bottom", pady=15, padx=20)

    # ---------------------------------------------------------------------
    # Dashboard cards (statistics)
    # ---------------------------------------------------------------------
    def _build_dashboard(self):
        self.cards_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.cards_frame.grid(row=1, column=0, sticky="ew", pady=(0, 5))

        # 6 columns for 5 metric cards + 1 threat level card
        for col in range(6):
            self.cards_frame.columnconfigure(col, weight=1, uniform="card")

        def _create_card(parent, title, value, col, value_color="#ffffff"):
            card = ctk.CTkFrame(parent, corner_radius=10, fg_color="#242424")
            card.grid(row=0, column=col, padx=5, pady=2, sticky="nsew")
            
            lbl_title = ctk.CTkLabel(card, text=title, font=("Helvetica", 11, "bold"), text_color="#aaaaaa")
            lbl_title.pack(pady=(5, 0))
            
            lbl_value = ctk.CTkLabel(card, text=value, font=("Helvetica", 18, "bold"), text_color=value_color)
            lbl_value.pack(pady=(0, 5))
            
            return lbl_value

        self.lbl_total = _create_card(self.cards_frame, "Total Packets", "0", 0, "#ffffff")
        self.lbl_tcp = _create_card(self.cards_frame, "TCP Traffic", "0", 1, "#ffffff")
        self.lbl_udp = _create_card(self.cards_frame, "UDP Traffic", "0", 2, "#ffffff")
        self.lbl_icmp = _create_card(self.cards_frame, "ICMP Traffic", "0", 3, "#ffffff")
        self.lbl_arp_alert = _create_card(self.cards_frame, "ARP Alerts", "0", 4, "#ff4444")

        # Threat Level Card
        self.card_threat = ctk.CTkFrame(self.cards_frame, corner_radius=10, fg_color="#242424")
        self.card_threat.grid(row=0, column=5, padx=5, pady=2, sticky="nsew")
        ctk.CTkLabel(self.card_threat, text="Threat Level", font=("Helvetica", 11, "bold"), text_color="#aaaaaa").pack(pady=(5, 0))
        self.lbl_threat_val = ctk.CTkLabel(self.card_threat, text="LOW", font=("Helvetica", 18, "bold"), text_color="#00ff88")
        self.lbl_threat_val.pack(pady=(0, 5))

    def _update_threat_level(self):
        if self.arp_alert_cnt == 0:
            self.lbl_threat_val.configure(text="INFO", text_color="#aaaaaa")
        elif self.arp_alert_cnt <= 2:
            self.lbl_threat_val.configure(text="LOW", text_color="#00ff88")
        elif self.arp_alert_cnt <= 5:
            self.lbl_threat_val.configure(text="MEDIUM", text_color="#ffaa00")
        elif self.arp_alert_cnt <= 10:
            self.lbl_threat_val.configure(text="HIGH", text_color="#ff4444")
        else:
            self.lbl_threat_val.configure(text="CRITICAL", text_color="#ff0000")

    # ---------------------------------------------------------------------
    # Live Alerts Panel
    # ---------------------------------------------------------------------
    def _build_live_alerts(self):
        self.alerts_frame = ctk.CTkFrame(self.main_frame, corner_radius=10, fg_color="#242424")
        self.alerts_frame.grid(row=2, column=0, sticky="ew", pady=(0, 15))
        
        lbl_alerts = ctk.CTkLabel(self.alerts_frame, text=" Live Security Alerts", font=("Helvetica", 14, "bold"), text_color="#ff4444")
        lbl_alerts.pack(anchor="w", padx=10, pady=(5, 5))
        
        # Use a Treeview for alerts
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Alerts.Treeview", background="#1a1a1a", foreground="#ff6666", fieldbackground="#1a1a1a",
                        borderwidth=0, font=("Courier", 11))
        style.configure("Alerts.Treeview.Heading", background="#333333", foreground="white", font=("Helvetica", 11, "bold"))
        style.map("Alerts.Treeview.Heading", background=[('active', '#444444')])

        columns = ("timestamp", "severity", "type", "message")
        self.tree_alerts = ttk.Treeview(self.alerts_frame, columns=columns, show="headings", style="Alerts.Treeview", height=3)
        
        self.tree_alerts.heading("timestamp", text="Timestamp")
        self.tree_alerts.heading("severity", text="Severity")
        self.tree_alerts.heading("type", text="Alert Type")
        self.tree_alerts.heading("message", text="Details")
        
        self.tree_alerts.column("timestamp", width=180, minwidth=150, anchor="w", stretch=False)
        self.tree_alerts.column("severity", width=100, minwidth=80, anchor="center", stretch=False)
        self.tree_alerts.column("type", width=150, minwidth=120, anchor="w", stretch=False)
        self.tree_alerts.column("message", width=400, minwidth=300, anchor="w", stretch=True)
        
        scrollbar = ttk.Scrollbar(self.alerts_frame, orient="vertical", command=self.tree_alerts.yview)
        self.tree_alerts.configure(yscrollcommand=scrollbar.set)
        
        self.tree_alerts.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=(0, 10))
        scrollbar.pack(side="right", fill="y", padx=(0, 10), pady=(0, 10))

    # ---------------------------------------------------------------------
    # Table for live packet view
    # ---------------------------------------------------------------------
    def _build_table(self):
        self.table_frame = ctk.CTkFrame(self.main_frame, fg_color="#242424", corner_radius=10)
        self.table_frame.grid(row=3, column=0, sticky="nsew")
        self.table_frame.columnconfigure(0, weight=1)
        self.table_frame.rowconfigure(1, weight=1)

        self.table_header_frame = ctk.CTkFrame(self.table_frame, fg_color="transparent")
        self.table_header_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(5, 5))
        self.table_header_frame.columnconfigure(0, weight=1)

        lbl_table = ctk.CTkLabel(self.table_header_frame, text=" Live Traffic Capture", font=("Helvetica", 14, "bold"), text_color="#ffffff")
        lbl_table.grid(row=0, column=0, sticky="w")
        
        self.btn_clear_captures = ctk.CTkButton(self.table_header_frame, text="Clear Captures", width=120, height=28, fg_color="#C0392B", hover_color="#E74C3C", command=self.clear_captures)
        self.btn_clear_captures.grid(row=0, column=1, sticky="e")

        style = ttk.Style()
        style.configure("Packet.Treeview", background="#2b2b2b", foreground="#e0e0e0", rowheight=25, fieldbackground="#2b2b2b",
                        borderwidth=0, font=("Courier", 11))
        style.configure("Packet.Treeview.Heading", background="#333333", foreground="white", font=("Helvetica", 12, "bold"))
        style.map("Packet.Treeview", background=[('selected', '#1f538d')])
        style.map("Packet.Treeview.Heading", background=[('active', '#444444')])

        columns = ("timestamp", "src_ip", "dst_ip", "src_mac", "dst_mac", "protocol", "length")
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show="headings", style="Packet.Treeview", height=15)
        
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.heading("src_ip", text="Source IP")
        self.tree.heading("dst_ip", text="Destination IP")
        self.tree.heading("src_mac", text="Source MAC")
        self.tree.heading("dst_mac", text="Destination MAC")
        self.tree.heading("protocol", text="Protocol")
        self.tree.heading("length", text="Length")

        # Optimal widths for readability
        self.tree.column("timestamp", width=180, minwidth=150, anchor="center", stretch=True)
        self.tree.column("src_ip", width=160, minwidth=120, anchor="center", stretch=True)
        self.tree.column("dst_ip", width=160, minwidth=120, anchor="center", stretch=True)
        self.tree.column("src_mac", width=140, minwidth=120, anchor="center", stretch=True)
        self.tree.column("dst_mac", width=140, minwidth=120, anchor="center", stretch=True)
        self.tree.column("protocol", width=90, minwidth=80, anchor="center", stretch=True)
        self.tree.column("length", width=80, minwidth=60, anchor="center", stretch=True)

        self.tree.bind("<<TreeviewSelect>>", self._on_packet_select)

        self.tree.tag_configure("tcp", background="#1a2b3c")
        self.tree.tag_configure("udp", background="#1d2e24")
        self.tree.tag_configure("icmp", background="#3b1f2b")
        self.tree.tag_configure("arp", background="#3d3a1f")
        self.tree.tag_configure("ipv6", background="#2a1f3d")
        self.tree.tag_configure("other", background="#2b2b2b")
        # specific tags for highlight
        self.tree.tag_configure("alert", background="#4a1a1a", foreground="#ff4444")

        scrollbar = ttk.Scrollbar(self.table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.grid(row=1, column=0, sticky="nsew", padx=(10,0), pady=(0,10))
        scrollbar.grid(row=1, column=1, sticky="ns", padx=(0,10), pady=(0,10))

    # ---------------------------------------------------------------------
    # Bottom Panels (Details & Talkers)
    # ---------------------------------------------------------------------
    def _build_bottom_panels(self):
        self.bottom_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.bottom_frame.grid(row=4, column=0, sticky="nsew", pady=(10, 0))
        self.bottom_frame.columnconfigure(0, weight=1, uniform="bottom")
        self.bottom_frame.columnconfigure(1, weight=1, uniform="bottom")
        self.bottom_frame.rowconfigure(0, weight=1)

        # Packet Details Panel
        self.details_frame = ctk.CTkFrame(self.bottom_frame, corner_radius=10, fg_color="#242424")
        self.details_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

        lbl_details = ctk.CTkLabel(self.details_frame, text=" Packet Details", font=("Helvetica", 14, "bold"), text_color="#00ccff")
        lbl_details.pack(anchor="w", padx=10, pady=(5, 5))

        self.txt_details = ctk.CTkTextbox(self.details_frame, fg_color="#1a1a1a", text_color="#e0e0e0", font=("Courier", 12), height=120)
        self.txt_details.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.txt_details.insert("1.0", "Select a packet from Live Traffic Capture\nto view detailed information.")
        self.txt_details.configure(state="disabled")

        # Top Talkers Panel
        self.talkers_frame = ctk.CTkFrame(self.bottom_frame, corner_radius=10, fg_color="#242424")
        self.talkers_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))

        lbl_talkers = ctk.CTkLabel(self.talkers_frame, text=" Top Talkers", font=("Helvetica", 14, "bold"), text_color="#ffffff")
        lbl_talkers.pack(anchor="w", padx=10, pady=(5, 5))

        self.txt_talkers = ctk.CTkTextbox(self.talkers_frame, fg_color="#1a1a1a", text_color="#e0e0e0", font=("Courier", 12), height=120)
        self.txt_talkers.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.txt_talkers.insert("1.0", "Waiting for traffic...")
        self.txt_talkers.configure(state="disabled")

    # ---------------------------------------------------------------------
    # Footer
    # ---------------------------------------------------------------------
    def _build_footer(self):
        self.footer_frame = ctk.CTkFrame(self.root, fg_color="#1a1a1a", height=30, corner_radius=0)
        self.footer_frame.grid(row=2, column=0, columnspan=2, sticky="ew")
        self.footer_frame.grid_propagate(False)
        self.footer_frame.columnconfigure(0, weight=1)
        self.footer_frame.columnconfigure(1, weight=1)
        self.footer_frame.columnconfigure(2, weight=1)

        self.lbl_footer_packets = ctk.CTkLabel(self.footer_frame, text="Packets Processed: 0", font=("Helvetica", 11), text_color="#aaaaaa")
        self.lbl_footer_packets.grid(row=0, column=0, sticky="w", padx=10)

        lbl_footer_status = ctk.CTkLabel(self.footer_frame, text="System Status: Stable", font=("Helvetica", 11), text_color="#00ff88")
        lbl_footer_status.grid(row=0, column=1)

        lbl_footer_version = ctk.CTkLabel(self.footer_frame, text="Application Version: 1.0.0", font=("Helvetica", 11), text_color="#aaaaaa")
        lbl_footer_version.grid(row=0, column=2, sticky="e", padx=10)

    def _log_system_event(self, event_type, message, severity="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.tree_alerts.insert("", "0", values=(timestamp, severity, event_type, message))
        if len(self.tree_alerts.get_children()) > 100:
            oldest = self.tree_alerts.get_children()[-1]
            self.tree_alerts.delete(oldest)

    # ---------------------------------------------------------------------
    # Run loop helper
    # ---------------------------------------------------------------------
    def run(self):
        self.root.mainloop()

    def _on_exit(self):
        if self.sniffer is not None:
            self.sniffer.stop_sniffing()
            self.sniffer = None
        self.root.quit()

    # ---------------------------------------------------------------------
    # Backend control methods
    # ---------------------------------------------------------------------
    def start_sniffing(self):
        if self.sniffer is not None:
            return
        self.sniffer = PacketSniffer(
            packet_callback=self._packet_callback,
            error_callback=self._sniffer_error_callback,
        )
        self.sniffer.start_sniffing()
        self.btn_start.configure(state="disabled", fg_color="#333333")
        self.btn_stop.configure(state="normal", fg_color="#C0392B")
        self.lbl_status.configure(text="ACTIVE", text_color="#00ff88")
        self._log_system_event("System", "Packet Capture Started")

    def stop_sniffing(self):
        if self.sniffer is None:
            return
        self.sniffer.stop_sniffing()
        self.sniffer = None
        self.btn_start.configure(state="normal", fg_color="#2b5c8f")
        self.btn_stop.configure(state="disabled", fg_color="#333333")
        self.lbl_status.configure(text="STOPPED", text_color="#ffaa00")
        self._log_system_event("System", "Packet Capture Stopped")

    # ---------------------------------------------------------------------
    # Error callback from PacketSniffer (runs in sniffer thread)
    # ---------------------------------------------------------------------
    def _sniffer_error_callback(self, msg):
        self.root.after(0, self._handle_sniffer_error, msg)

    def _handle_sniffer_error(self, msg):
        self.sniffer = None
        self.btn_start.configure(state="normal", fg_color="#2b5c8f")
        self.btn_stop.configure(state="disabled", fg_color="#333333")
        self.lbl_status.configure(text="ERROR", text_color="#ff4444")
        messagebox.showerror("Sniffer Error", msg)

    # ---------------------------------------------------------------------
    # Callback from PacketSniffer (runs in sniffer thread)
    # ---------------------------------------------------------------------
    def _packet_callback(self, packet_info):
        self.root.after(0, self._handle_packet, packet_info)

    def _update_filters(self):
        protocols = set()
        if self.var_tcp.get(): protocols.add("TCP")
        if self.var_udp.get(): protocols.add("UDP")
        if self.var_icmp.get(): protocols.add("ICMP")
        if self.var_arp.get(): protocols.add("ARP")
        if self.var_ipv6.get(): protocols.add("IPv6")
        if self.var_other.get(): protocols.add("OTHER")
        self.active_protocols = protocols
        self._refresh_table(search_query=self._get_active_search())

    def _search_packets(self):
        query = self.search_var.get().strip()
        self._refresh_table(search_query=query)

    def _clear_search(self):
        self.search_var.set("")
        self._refresh_table()

    def clear_captures(self):
        with self.lock:
            self.packets = []
            self.tcp_cnt = 0
            self.udp_cnt = 0
            self.icmp_cnt = 0
            self.total_cnt = 0
            self.src_ip_counter.clear()
            self.dst_ip_counter.clear()
            
            self.lbl_tcp.configure(text="0")
            self.lbl_udp.configure(text="0")
            self.lbl_icmp.configure(text="0")
            self.lbl_total.configure(text="0")
            self.lbl_live_counter.configure(text="Total Captured: 0")
            self.lbl_footer_packets.configure(text="Packets Processed: 0")
            
            self.txt_talkers.configure(state="normal")
            self.txt_talkers.delete("1.0", "end")
            self.txt_talkers.insert("1.0", "Waiting for traffic...")
            self.txt_talkers.configure(state="disabled")
            
            self.txt_details.configure(state="normal")
            self.txt_details.delete("1.0", "end")
            self.txt_details.insert("1.0", "Select a packet from Live Traffic Capture\nto view detailed information.")
            self.txt_details.configure(state="disabled")
            
            self.tree.delete(*self.tree.get_children())

    def _get_active_search(self):
        return self.search_var.get().strip()

    @staticmethod
    def _classify_protocol(proto_str):
        upper = proto_str.upper()
        if upper in ("TCP", "UDP", "ICMP", "ARP", "IPv6"):
            return upper
        return "OTHER"

    def _refresh_table(self, search_query=""):
        self.tree.delete(*self.tree.get_children())
        query_lower = search_query.lower()
        with self.lock:
            row_idx = 0
            for pkt in self.packets:
                proto_raw = pkt.get("protocol", "")
                proto_cat = self._classify_protocol(proto_raw)
                if proto_cat not in self.active_protocols:
                    continue
                
                if query_lower:
                    src = pkt.get("source_ip", "").lower()
                    dst = pkt.get("destination_ip", "").lower()
                    proto = proto_raw.lower()
                    if query_lower not in src and query_lower not in dst and query_lower not in proto:
                        continue
                
                # Check if it was an alert packet (for highlighting)
                is_alert = pkt.get("_is_alert", False)
                tag = "alert" if is_alert else proto_cat.lower()
                
                self.tree.insert("", "end", values=(
                    pkt.get("timestamp", ""),
                    pkt.get("source_ip", ""),
                    pkt.get("destination_ip", ""),
                    pkt.get("source_mac", ""),
                    pkt.get("destination_mac", ""),
                    pkt.get("protocol", ""),
                    pkt.get("length", "")
                ), tags=(tag,))
                row_idx += 1
            self.tree.yview_moveto(1.0)

    def _handle_packet(self, packet_info):
        log_packet(packet_info)
        with self.lock:
            # Track if this packet caused an alert
            packet_info["_is_alert"] = False
            self.packets.append(packet_info)
            
            # Add to Top Talkers
            src = packet_info.get("source_ip", "N/A")
            dst = packet_info.get("destination_ip", "N/A")
            if src and src != "N/A":
                self.src_ip_counter[src] += 1
            if dst and dst != "N/A":
                self.dst_ip_counter[dst] += 1

            self.total_cnt += 1
            self.lbl_total.configure(text=str(self.total_cnt))
            self.lbl_live_counter.configure(text=f"Total Captured: {self.total_cnt}")
            
            proto_raw = packet_info.get("protocol", "")
            proto_upper = proto_raw.upper()
            if proto_upper == "TCP":
                self.tcp_cnt += 1
                self.lbl_tcp.configure(text=str(self.tcp_cnt))
            elif proto_upper == "UDP":
                self.udp_cnt += 1
                self.lbl_udp.configure(text=str(self.udp_cnt))
            elif proto_upper == "ICMP":
                self.icmp_cnt += 1
                self.lbl_icmp.configure(text=str(self.icmp_cnt))
            elif proto_upper == "ARP":
                if packet_info.get("arp_op") == "ARP Request":
                    self._log_system_event("Network Event", f"ARP Request Detected from {packet_info.get('arp_src_ip', 'Unknown')}", severity="INFO")

            self.lbl_footer_packets.configure(text=f"Packets Processed: {self.total_cnt}")

            alert_msg = self.detector.process_packet(packet_info)
            if alert_msg:
                log_alert(alert_msg)
                packet_info["_is_alert"] = True
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                # Set severity strictly to WARNING as per detection flowchart
                severity = "WARNING"
                
                self.alerts.append({"timestamp": timestamp, "severity": severity, "type": "ARP Spoofing", "message": alert_msg})
                
                self.arp_alert_cnt += 1
                self.lbl_arp_alert.configure(text=str(self.arp_alert_cnt))
                self._update_threat_level()
                
                self._log_system_event("Potential ARP Spoofing Alert", alert_msg, severity=severity)

            # Table update
            proto_cat = self._classify_protocol(proto_raw)
            show = proto_cat in self.active_protocols
            if show:
                query_lower = self._get_active_search().lower()
                if query_lower:
                    src = packet_info.get("source_ip", "").lower()
                    dst = packet_info.get("destination_ip", "").lower()
                    proto_l = proto_raw.lower()
                    if query_lower not in src and query_lower not in dst and query_lower not in proto_l:
                        show = False
            if show:
                current_rows = len(self.tree.get_children())
                is_alert = packet_info.get("_is_alert", False)
                tag = "alert" if is_alert else proto_cat.lower()
                
                self.tree.insert("", "end", values=(
                    packet_info.get("timestamp", ""),
                    packet_info.get("source_ip", ""),
                    packet_info.get("destination_ip", ""),
                    packet_info.get("source_mac", ""),
                    packet_info.get("destination_mac", ""),
                    packet_info.get("protocol", ""),
                    packet_info.get("length", "")
                ), tags=(tag,))
                
                if current_rows + 1 > 500:
                    oldest = self.tree.get_children()[0]
                    self.tree.delete(oldest)
                    
            self.tree.yview_moveto(1.0)

    # ---------------------------------------------------------------------
    # Export CSV report
    # ---------------------------------------------------------------------
    def export_report(self):
        if not self.packets:
            messagebox.showwarning("Export", "No packets captured to export.")
            return
        try:
            # We don't want to export the internal '_is_alert' flag
            clean_packets = [{k: v for k, v in p.items() if k != '_is_alert'} for p in self.packets]
            report_path = generate_csv_report(clean_packets)
            messagebox.showinfo("Export", f"Report saved to:\n{report_path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _on_packet_select(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        item = self.tree.item(selected[0])
        values = item['values']
        if not values:
            return

        details = (
            f"Timestamp:       {values[0]}\n"
            f"Source IP:       {values[1]}\n"
            f"Destination IP:  {values[2]}\n"
            f"Source MAC:      {values[3]}\n"
            f"Destination MAC: {values[4]}\n"
            f"Protocol:        {values[5]}\n"
            f"Packet Length:   {values[6]} bytes\n"
            f"Flags:           N/A\n"
        )
        self.txt_details.configure(state="normal")
        self.txt_details.delete("1.0", "end")
        self.txt_details.insert("1.0", details)
        self.txt_details.configure(state="disabled")

    def _update_top_talkers(self):
        with self.lock:
            top_src = self.src_ip_counter.most_common(5)
            top_dst = self.dst_ip_counter.most_common(5)

        text = "Top Source IPs:\n"
        for ip, count in top_src:
            if ip and ip != "N/A":
                text += f"  {ip.ljust(15)} → {count} packets\n"
        
        text += "\nTop Destination IPs:\n"
        for ip, count in top_dst:
            if ip and ip != "N/A":
                text += f"  {ip.ljust(15)} → {count} packets\n"

        self.txt_talkers.configure(state="normal")
        self.txt_talkers.delete("1.0", "end")
        self.txt_talkers.insert("1.0", text)
        self.txt_talkers.configure(state="disabled")

    def export_alerts(self):
        if not self.alerts:
            messagebox.showwarning("Export", "No alerts to export.")
            return
        try:
            report_path = generate_alerts_report(self.alerts)
            messagebox.showinfo("Export", f"Alerts report saved to:\n{report_path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    # ---------------------------------------------------------------------
    # Simulated Testing
    # ---------------------------------------------------------------------
    def run_arp_test(self):
        """Safely simulate an ARP spoofing attack without touching the network."""
        alert_msg = self.detector.test_spoof_sequence("192.168.1.1", "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66")
        if alert_msg:
            with self.lock:
                log_alert(alert_msg)
                
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                severity = "WARNING"
                self.alerts.append({"timestamp": timestamp, "severity": severity, "type": "ARP Spoofing", "message": alert_msg})
                
                self.arp_alert_cnt += 1
                self.lbl_arp_alert.configure(text=str(self.arp_alert_cnt))
                self._update_threat_level()
                
                self._log_system_event("Simulated Threat (Test)", alert_msg, severity=severity)

if __name__ == "__main__":
    Dashboard().run()
