from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):

    if IP in packet:

        source = packet[IP].src
        destination = packet[IP].dst

        # Protocol and port
        if TCP in packet:
            protocol = "TCP"
            port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            port = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"
            port = "-"

        else:
            protocol = "Other"
            port = "-"

        # Payload
        if Raw in packet:
            payload = bytes(packet[Raw].load).decode(
                errors="replace"
            )[:100]
        else:
            payload = "No payload"

        print(
            f"Source: {source} | "
            f"Destination: {destination} | "
            f"Protocol: {protocol} | "
            f"Port: {port} | "
            f"Payload: {payload}"
        )


print("==============================")
print("     BASIC NETWORK SNIFFER")
print("==============================")
print("Capturing packets...")
print("Press Ctrl+C to stop.")
print()

sniff(prn=packet_callback, store=False)