#!/usr/bin/env python

import scapy.all as scapy


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="port 80") # Sniff packets on the specified interface

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip) # Create an ARP request packet
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # Create a broadcast packet
    arp_request_broadcast = broadcast/arp_request # Combine the broadcast and ARP request packets
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # Send the packet and receive the response
    return answered_list[0][1].hwsrc # Get the MAC address from the response
               

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2: # Check if the packet is an ARP response
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc
            if real_mac != response_mac:
                print("[+] ARP Spoofing detected!")
                print("[+] IP: " + packet[scapy.ARP].psrc + " is at " + response_mac)
                print("[+] But it should be at " + real_mac)
                print("\n")
        except IndexError:
            pass
# Start sniffing on the specified interface

sniff("eth0")

