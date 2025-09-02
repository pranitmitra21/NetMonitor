from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP
import time
from collections import Counter

# Detect protocol type
def detect_protocol(pkt):
    if pkt.haslayer(ICMP):
        return "ICMP"
    elif pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if sport == 80 or dport == 80:
            return "HTTP"
        elif sport == 443 or dport == 443:
            return "HTTPS"
        else:
            return "TCP"
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        if sport == 443 or dport == 443:
            return "QUIC/HTTPS"
        elif sport == 53 or dport == 53:
            return "DNS"
        else:
            return "UDP"
    return "OTHER"

# Format packet line
def format_packet(pkt):
    proto = detect_protocol(pkt)
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        if pkt.haslayer(TCP):
            return f"[{proto}] {src}:{pkt[TCP].sport} -> {dst}:{pkt[TCP].dport}"
        elif pkt.haslayer(UDP):
            return f"[{proto}] {src}:{pkt[UDP].sport} -> {dst}:{pkt[UDP].dport}"
        elif pkt.haslayer(ICMP):
            return f"[{proto}] {src} -> {dst}"
    return f"[{proto}] Packet"

# Analyze packets (for both live & pcap)
def analyze_packets(packets, duration=None):
    protocols = Counter()
    talkers = Counter()

    for pkt in packets:
        proto = detect_protocol(pkt)
        protocols[proto] += 1
        if pkt.haslayer(IP):
            talkers[pkt[IP].src] += 1

    print("\n===== Capture Statistics =====")
    if duration:
        print(f"Capture Duration: {duration:.2f}s")
    print(f"Total Packets: {len(packets)}\n")

    print("Protocol Breakdown:")
    for proto, count in protocols.most_common():
        pct = (count / len(packets)) * 100
        print(f"  {proto}: {count} ({pct:.1f}%)")

    print("\nTop 5 Talkers (Source IPs):")
    for ip, count in talkers.most_common(5):
        print(f"  {ip}: {count} packets")

# Live capture
def live_capture():
    print("\nOptions:")
    print("  1. Capture All Packets")
    print("  2. Capture Only TCP")
    print("  3. Capture Only UDP")
    print("  4. Capture Only ICMP")
    print("  5. Capture HTTP (Port 80)")
    print("  6. Capture HTTPS (Port 443)")
    choice = input("Select option: ")

    filters = {
        "1": "", 
        "2": "tcp",
        "3": "udp",
        "4": "icmp",
        "5": "tcp port 80",
        "6": "tcp port 443"
    }
    flt = filters.get(choice, "")

    print("\nCapture Mode:")
    print("  1. Run until Ctrl+C")
    print("  2. Run for fixed time")
    mode = input("Select mode: ")

    packets = []
    start_time = time.time()

    try:
        if mode == "2":
            duration = int(input("Enter capture duration in seconds: "))
            print(f"\n[+] Capturing packets for {duration}s... showing first 10 packets live")
            packets = sniff(filter=flt, timeout=duration)
        else:
            print("\n[+] Capturing packets... Press Ctrl+C to stop")
            packets = sniff(filter=flt)
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user")

    end_time = time.time()
    duration = end_time - start_time

    for pkt in packets[:10]:
        print(format_packet(pkt))

    analyze_packets(packets, duration)

    save = input("Save packets to PCAP file? (y/n): ")
    if save.lower() == "y":
        fname = input("Enter filename (e.g., capture.pcap): ")
        from scapy.utils import wrpcap
        wrpcap(fname, packets)
        print(f"[+] Saved to {fname}")

# PCAP analysis
def analyze_pcap():
    fname = input("Enter PCAP filename: ")
    try:
        packets = rdpcap(fname)
    except FileNotFoundError:
        print("[!] File not found")
        return

    print(f"\n[+] Analyzing {fname}, showing first 10 packets")
    for pkt in packets[:10]:
        print(format_packet(pkt))

    analyze_packets(packets)

# Main menu
def main():
    print("1. Capture Live Traffic (with time & protocol filter)")
    print("2. Analyze PCAP File (same analysis & format)")
    choice = input("Select option: ")

    if choice == "1":
        live_capture()
    elif choice == "2":
        analyze_pcap()
    else:
        print("[!] Invalid choice")

if __name__ == "__main__":
    main()
