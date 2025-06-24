# Enhanced Network Security Analyzer

This Python project captures and analyzes network packets in real-time using Scapy. It logs detailed information about TCP, UDP, and ICMP packets, detects potential SYN scans, and keeps track of packet statistics.

## Features

- Real-time network packet sniffing
- Detects suspicious SYN packets (possible port scans)
- Logs packet details with timestamps to a text file (`network_logs.txt`)
- Saves packet info to a CSV file (`network_logs.csv`)
- GeoIP lookup for source IP addresses (country information)
- Maintains counts of total packets and protocol-specific packets
- Handles graceful shutdown on Ctrl+C (SIGINT)

## Requirements

- Python 3.x
- Scapy
- Requests library

## Installation

```bash
pip install scapy requests
