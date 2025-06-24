from scapy.all import sniff, IP, TCP, UDP, ICMP
import logging
import csv
import requests
from datetime import datetime
import signal
import sys

# Setup logging
logging.basicConfig(
    filename="network_logs.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# CSV setup
csv_file = open("network_logs.csv", "w", newline="")
csv_writer = csv.writer(csv_file)
csv_writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "Info", "GeoIP Country"])

# IP blacklist (can be expanded)
blacklist = {"192.168.1.100", "10.0.0.5"}

# Statistics
packet_stats = {
    "total": 0,
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0
}

stop_sniffing = False  # Global flag to stop sniffing

def signal_handler(sig, frame):
    global stop_sniffing
    print("\n🚨 Ctrl+C pressed, stopping sniffing...")
    stop_sniffing = True

signal.signal(signal.SIGINT, signal_handler)

def geoip_lookup(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        data = response.json()
        return data.get("country", "Unknown")
    except:
        return "Lookup Failed"

def packet_callback(packet):
    global stop_sniffing
    if stop_sniffing:
        return True  # Immediately stop, no extra prints

    # Your existing code here
    packet_stats["total"] += 1

    protocol = "Other"
    src_ip = dst_ip = info = "-"

    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if TCP in packet:
            packet_stats["TCP"] += 1
            protocol = "TCP"
            tcp_layer = packet[TCP]
            info = f"{src_ip} --> {dst_ip} | TCP Dst Port: {tcp_layer.dport}"
            if tcp_layer.flags == "S":
                alert = f"[ALERT] SYN Packet from {src_ip} to port {tcp_layer.dport}"
                print(alert)
                logging.warning(alert)

        elif UDP in packet:
            packet_stats["UDP"] += 1
            protocol = "UDP"
            udp_layer = packet[UDP]
            info = f"{src_ip} --> {dst_ip} | UDP Dst Port: {udp_layer.dport}"

        elif ICMP in packet:
            packet_stats["ICMP"] += 1
            protocol = "ICMP"
            info = f"{src_ip} --> {dst_ip} | ICMP Packet"

        geo_country = geoip_lookup(src_ip)

        if src_ip in blacklist:
            blacklist_alert = f"[BLACKLISTED] Packet from blacklisted IP {src_ip}"
            print(blacklist_alert)
            logging.error(blacklist_alert)

        print(f"{protocol}: {info} | Country: {geo_country}")
        logging.info(info)
        csv_writer.writerow([datetime.now(), src_ip, dst_ip, protocol, info, geo_country])


print("🔍 Enhanced Network Security Analyzer is running... Press Ctrl+C to stop.\n")

sniff(prn=packet_callback, store=0, stop_filter=lambda x: stop_sniffing)

print("\n🚨 Sniffing stopped. Log files saved (network_logs.txt and network_logs.csv).")
print(f"📊 Packet Stats: {packet_stats}")
csv_file.close()
sys.exit(0)
