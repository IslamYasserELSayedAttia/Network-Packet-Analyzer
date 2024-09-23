from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

# Callback function to handle each captured packet
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        # Check for TCP/UDP and extract relevant info
        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            proto = "Other"
            sport = None
            dport = None

        # Print packet info
        print(f"IP Packet: {ip_src} -> {ip_dst} | Protocol: {proto}")
        
        if sport and dport:
            print(f"Source Port: {sport} | Destination Port: {dport}")
        
        # Print payload if available
        if packet.haslayer(Raw):
            print(f"Payload: {packet[Raw].load}")
        
        print("\n" + "="*50 + "\n")

# Sniff packets
def start_sniffing(interface=None):
    print("Starting packet capture...")
    sniff(iface=interface, prn=packet_callback, store=0)

# If no interface is provided, default to capturing on all available interfaces
if __name__ == "__main__":
    interface = input("Enter the interface to sniff (leave blank for default): ")
    start_sniffing(interface if interface else None)
