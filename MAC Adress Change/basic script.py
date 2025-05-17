#!/usr/bin/env python

import subprocess
import optparse 

def get_arguments():
    parser = optparse.OptionParser() # Create an option parser
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change MAC address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address") # Add an option for the new MAC address
    (options, arguments) = parser.parse_args() # Parse the command line arguments
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info.") # Error message if no interface is specified
    elif not options.new_mac:
        parser.error("[-] Please specify a new MAC address, use --help for more info.") # Error message if no MAC address is specified
    return (options, arguments) # Return the options and arguments

def change_mac(interface, new_mac):
    print("Changing MAC address for interface:", interface + " to " + new_mac)
    subprocess.call(["ifconfig", interface, "down"]) # Bring the interface down
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac]) # Change the MAC address
    subprocess.call(["ifconfig", interface, "up"]) # Bring the interface up


options =  get_arguments() # Call the function to get command line arguments
change_mac(options.interface, options.new_mac) # Call the function to change the MAC address

