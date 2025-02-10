from scapy.all import sniff, wrpcap

def packet_callback(packet):
    print(packet.summary())

def start_sniffing(interface="wlan0", packet_count=100, save_to_file="captured_packets.pcap"):
    print(f"[*] Starting packet capture on {interface}...")
    
    packets = sniff(iface=interface, prn=packet_callback, count=packet_count)

    if save_to_file:
        wrpcap(save_to_file, packets)
        print(f"[+] Packets saved to {save_to_file}")

if __name__ == "__main__":
    interface = input("Enter network interface (default: wlan0): ") or "wlan0"
    packet_count = int(input("Enter number of packets to capture (default: 100): ") or 100)
    save_to_file = input("Enter file name to save packets (default: captured_packets.pcap): ") or "captured_packets.pcap"

    start_sniffing(interface, packet_count, save_to_file)
