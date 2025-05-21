#!/usr/bin/env python

import netfilterqueue


def process_packet(packet):
    print(packet) # Print the packet
    packet.accept() # Accept the packet

queue = netfilterqueue.NetfilterQueue() # Create a NetfilterQueue object
queue.bind(0, process_packet) # Bind the queue to the process_packet function
queue.run() # Start the queue

