from scapy.all import IP, TCP, ICMP, UDP, ARP, sniff
import scapy.error
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse 
import sys 
import time
from datetime import datetime 
import keyboard 
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-c", "--count", type=int, help="Enter number of packets to capture")
parser.add_argument("-f", "--filter-by-protocol", type=str, nargs='*', help="Filter for protocol")
parser.add_argument("-he", "--header", type=str, help="Extract and display the specified header.")
parser.add_argument("-src", "--source_ip", type=str, help="Filter for source ip address")
parser.add_argument("-dst", "--destination_ip", type=str, help="Filter for destination ip address")
args = parser.parse_args()

protocols = {
    "IP": IP,
    "TCP": TCP,
    "ICMP": ICMP,
    "ARP": ARP,
    "UDP": UDP,
    "HTTP": HTTP
}

def process(packet) : 
    if keyboard.is_pressed('q') :
        print("Scan ended")
        sys.exit(0)
    time.sleep(0.1)

     
    print(packet.summary())

             
def process2(packet) :
    print(packet.summary())

def ip_scan(packet) : 
    if keyboard.is_pressed('q') :
        print("Scan ended")
        sys.exit(0)
    time.sleep(0.1)
    try :
        if (packet.haslayer(IP)) : 
            if args.source_ip is not None and args.destination_ip is not None : 
                if (packet[IP].src == args.source_ip and packet[IP].dst == args.destination_ip) : 
                    print(packet.summary())

            elif args.source_ip is not None : 
                if (packet[IP].src == args.source_ip) : 
                    print(packet.summary())

            elif args.destination_ip is not None : 
                if (packet[IP].dst == args.destination_ip) : 
                    print(packet.summary())

    except : 
        print("An unexcepcted exception occurred")

def header_scan(packet) :
    if keyboard.is_pressed('q') :
        print("Scan ended")
        sys.exit(0)
    time.sleep(0.1)
    try : 
        header = protocols[args.header.upper()]
        if packet.haslayer(header) : 
            print(packet[header].show())
    except : 
        print("Please enter valid header")
        sys.exit(0)

def protocol_filtered_scan(protocol) :
    list_of_filters = [] 
    for filter in args.protocol :
        filter = "".join(char for char in filter if char.isalpha()).lower() 
        list_of_filters.append(filter)
        filters = " or ".join(list_of_filters)
        print(filters)

    if (args.count != None) : 
        try :
            sniff(prn=process, count = args.count, filter=filters, store=False)

        except scapy.error.Scapy_Exception : #if the filter entered is incorrect
            print("Please choose a valid filter")
            sys.exit(0)

    else :
        try :
            sniff(prn=process, filter=filters, store=False)

        except scapy.error.Scapy_Exception : #if the filter entered is incorrect
            print("Please choose a valid filter")
            sys.exit(0)

def main() :
    if args.protocol != None : 
        protocol_filtered_scan(args.protocol)

    elif args.header != None : 
        sniff(prn=header_scan, store=False)

    else : 
        sniff(prn=process, store=False)

if __name__== "__main__" : 
    main()
