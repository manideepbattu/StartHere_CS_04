from scapy.all import sniff, IP, TCP, UDP, ICMP
import logging
import datetime

# Configure logging
logging.basicConfig(filename='packet_log.txt', level=logging.INFO, 
                    format='%(asctime)s - %(message)s')

# Dictionary to count packets by protocol
packet_counts = {"IP": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "Others": 0}

def packet_handler(packet):
    try:
        protocol = "Others"

        # Check if packet has an IP layer
        if IP in packet:
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst

            # Determine protocol and increment count
            if TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"
            elif ICMP in packet:
                protocol = "ICMP"
            else:
                protocol = "IP"
            
            packet_counts[protocol] += 1

            print(f"Source IP: {source_ip}, Destination IP: {dest_ip}, Protocol: {protocol}")
            logging.info(f"Source IP: {source_ip}, Destination IP: {dest_ip}, Protocol: {protocol}")

            # Check and print payload for TCP or UDP packets
            if TCP in packet or UDP in packet:
                payload = bytes(packet[IP].payload)
                print(f"Payload: {payload}\n")
                logging.info(f"Payload: {payload}")
        else:
            packet_counts["Others"] += 1

    except Exception as e:
        print(f"Error processing packet: {e}")
        logging.error(f"Error processing packet: {e}")

def main():
    print("Starting packet sniffer with enhancements...")
    print("Press Ctrl+C to stop...")
    
    # Specify number of packets to capture and filter option
    try:
        packet_count = int(input("Enter number of packets to capture (0 for unlimited): "))
        filter_option = input("Enter filter (e.g., 'tcp', 'udp', 'ip', 'icmp' or leave empty for no filter): ").strip()

        if filter_option:
            sniff(prn=packet_handler, store=0, count=(packet_count if packet_count > 0 else None), filter=filter_option)
        else:
            sniff(prn=packet_handler, store=0, count=(packet_count if packet_count > 0 else None))
    
    except KeyboardInterrupt:
        print("\nPacket capturing stopped.")
        print("Final packet counts:")
        for proto, count in packet_counts.items():
            print(f"{proto}: {count}")
    except Exception as e:
        print(f"Error starting sniffer: {e}")

if __name__ == "__main__":
    
    main()
