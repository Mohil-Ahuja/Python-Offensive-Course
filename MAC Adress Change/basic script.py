#run with python3
# This script changes the MAC address of a network interface on a Linux system.
# example usage: python3 basic_script.py -i eth0 -m 00:11:22:33:44:55

#!/usr/bin/env python

import subprocess
import optparse 
import re

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

def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface]) # Check the output of the ifconfig command

    mac_address_search_result = re.search(r"(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)", str(ifconfig_result)) # Search for the MAC address in the output

    if mac_address_search_result: # If a MAC address is found
        return mac_address_search_result.group(0)
    else:
        print("Could not read MAC address") # Print an error message if no MAC address is found


options =  get_arguments() # Call the function to get command line arguments

current_mac = get_current_mac(options.interface) # Call the function to get the current MAC address
print("Current MAC = " + str(current_mac)) # Print the current MAC address

change_mac(options.interface, options.new_mac) # Call the function to change the MAC address

current_mac = get_current_mac(options.interface) # Call the function to get the current MAC address

if current_mac == options.new_mac: # Check if the MAC address was changed successfully
    print("MAC address was successfully changed to " + current_mac) # Print a success message
else:
    print("MAC address did not get changed.")



