#!/usr/bin/env python
# This script scans a network for active devices using ARP requests.
# example usage: python3 network_scanner.py
# for help use scapy.ls(scapy.ARP()) to see all the options available for ARP
# for summary use scapy.ls() to see all the options available for all protocols
# to print the details of the arp packet use arp_request.show()

import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP / IP range.")
    options, arguments = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip) # Create an ARP request packet
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # Create a broadcast packet
    arp_request_broadcast = broadcast/arp_request # Combine the broadcast and ARP request packets
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # Send the packet and receive the response
    
    print("IP\t\t\tMAC Address\n-----------------------------------")
    clients_list = []
    for element in answered_list:
        client_dict = {"ip" : element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
        
    return clients_list

def print_result(clients_list):
    print("IP\t\t\tMAC Address\n-----------------------------------")
    for client in clients_list:
        print(client["ip"] + "\t\t" + client["mac"]) # Print the IP and MAC address of each device


options = get_arguments() # Call the function to get command line arguments
scan_result = scan(options.target) # Call the scan function with the specified IP address
print_result(scan_result) # Call the print_result function to display the scan results  
