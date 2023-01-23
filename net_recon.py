#!/usr/bin/python3

from scapy.all import *
import sys
import os

# Global variables for sharing between functions
ip_mac_mapping = {}  # Maintains 1:M mapping of {IP Address, [Mac Address0, ...Mac AddressN}
ip_packets_mapping = {}  # Maintains 1:1 mapping of {IP Address, Packet Count}
interface = ""
mode = ""
host_count = 0


def clear():
    # for windows
    if os.name == 'nt':
        os.system('cls')

    # for mac and linux
    else:
        os.system('clear')


def print_term_header():
    clear()

    if host_count == 1:
        print("Interface: " + str(interface).ljust(21, " ") + "Mode: " + str(mode).ljust(26, " ") + "Found " + str(
            host_count) + " host")
    else:
        print("Interface: " + str(interface).ljust(21, " ") + "Mode: " + str(mode).ljust(26, " ") + "Found " + str(
            host_count) + " hosts")

    print('-' * 80)
    if mode == "Passive":
        print('MAC\t\t\t\tIP\t\t\t\tHost Activity')
    else:
        print('MAC\t\t\t\tIP')
    print('-' * 80)


def validate_args(args):
    #  Expect "-i" or "-iface" in arg[1]
    #  Expect the interface name in arg[2]
    #  Expect "-p", "--passive", "-a" or "--active" in arg[3]

    if args[1] in ["-i", "--iface"]:
        arg_iface = args[2]
    else:
        return -1
    if args[3] in ["-p", "--passive"]:
        arg_mode = "Passive"
    elif args[3] in ["-a", "--active"]:
        arg_mode = "Active"
    else:
        return -2

    return arg_iface, arg_mode


def packet_handler(pkt):
    global host_count

    source_ip = "?"
    source_mac = "?"

    try:
        arp = pkt[ARP]
    except:
        # We should not be getting any non-ARP packets, but this gracefully handles it if it happens
        return

    if arp.op == 2:  # "who-has":

        try:
            source_ip = arp.psrc
        except:
            pass  # Stick with the default ? value

        try:
            source_mac = arp.hwsrc
        except:
            pass  # Stick with the default ? value

        # If we already have this IP address in the dictionary
        if source_ip in ip_mac_mapping:
            current_macs = ip_mac_mapping[source_ip]  # Get the list of currently mapped Mac Addresses
            ip_packets_mapping[source_ip] = ip_packets_mapping[source_ip] + 1  # Increment the packet count for this IP

            # If this is a new Mac address then add it to the current IP : Mac Address mapping
            if source_mac not in current_macs:
                current_macs.append(source_mac)
                ip_mac_mapping[source_ip] = current_macs

        # If this is a newly discovered IP address, add the IP and Mac address to the mapping
        else:
            current_macs = [source_mac]
            ip_mac_mapping[source_ip] = current_macs
            ip_packets_mapping[source_ip] = 1  # Start the packet count for this IP address at 1

        host_count = len(ip_mac_mapping)

        # Sort the IP Address / Packet count dictionary based on descending packet count
        sorted_ip_packets_mapping = dict(sorted(ip_packets_mapping.items(), key=operator.itemgetter(1), reverse=True))

        # Print the list of IP address, Mac addresses and packet counts in the sorted order
        print_term_header()

        for ip, count in sorted_ip_packets_mapping.items():
            for mac in ip_mac_mapping[ip]:
                # Print each mac / ip mapping using ljust to ensure ip address column alignment and rjust to align
                # packet count column
                print(str(mac).ljust(32, " ") + str(ip).ljust(32, " ") + str(ip_packets_mapping[ip]).rjust(13, " "))


def passive_scan():
    global interface
    try:
        # filter = arp so we only process ARP messages
        # store = 0 so we don't run out of memory  on a long scan
        sniff(iface=interface, prn=packet_handler, filter="arp", store=0)
    except:
        print("Unable to sniff network interface '" + str(interface) + "'. Check that the interface name is correct "
                                                                       "and that your are running with admin user  "
                                                                       "permissions.")

def active_recon():
    global interface, host_count

    # Get the source ip for this device, and get network id (first 3 parts of)
    my_ip = get_if_addr(interface)
    network_id = my_ip.split(".")[0] + "." + my_ip.split(".")[1] + "." + my_ip.split(".")[2]

    print_term_header()

    # Ping each of the ip addresses in the network id range except this device's IP, over ICMP protocol
    # We're not going to send ICMP request to the .0 (network id) or the .255 (broadcast) IP addresses

    for host_id in range(1, 255):  # .0 and .255 will be ignored
        ip_address_to_ping = network_id + "." + str(host_id)
        if ip_address_to_ping != my_ip and host_id not in (0, 255):
            print("\nPinging " + str(ip_address_to_ping) + " ...")
            icmp_packet = IP(dst=ip_address_to_ping) / ICMP()
            response = srp(icmp_packet, timeout=2, verbose=0)

            # If an ICMP response is received within 2 seconds, then broadcast an ARP request for that IP address
            # to get the network adapter MAC address for the related IP
            if response is not None:
                answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address_to_ping),
                                           iface=interface, timeout=2, verbose=False)
                if len(answered) > 0:
                    # When ARP response is received, pull out the source MAC address and add to the ip_mac_mapping list
                    host_count = host_count + 1
                    source_macs = [answered[0][1].getlayer(ARP).hwsrc]
                    ip_mac_mapping[ip_address_to_ping] = source_macs

                # Display the header and the full list of found hosts
                print_term_header()
                for ip in ip_mac_mapping:
                    for mac in ip_mac_mapping[ip]:
                        print(str(mac) + '\t\t' + str(ip))


def help():
    print("usage: net_recon.py -i INTERFACE (-a | -p) \n")
    print("A script to passively or actively detect hosts on a network\n")
    print("optional arguments:")
    print("\t-a, --active\tLaunch in active move")
    print("\t-p, --passive\tLaunch in passive move\n")
    print("required named arguments:")
    print("\t-i, --iface INTERFACE\tSpecifies the network interface to use")


def main(args):
    global interface, mode

    if len(args) == 1:  # If only the script name was passed (no arguments)
        help()  # Call the help function and exit
        return
    elif len(args) != 4:
        print("This utility requires exactly 3 arguments!\n")
        help()
        return

    argument_check = validate_args(args)  # Read and validate the arguments passed

    if argument_check == -1:
        print("ERROR: You did not correctly specify the interface.")
        help()
    elif argument_check == -2:
        print("ERROR: You did not correctly specify active or passive mode.")
        help()
    else:
        interface, mode = argument_check
        print_term_header()

    if mode == "Passive":
        passive_scan()
    elif mode == "Active":
        active_recon()
    else:
        print("ERROR: Invalid mode '" + str(mode) + "' specified")


if __name__ == "__main__":
    main(sys.argv)
