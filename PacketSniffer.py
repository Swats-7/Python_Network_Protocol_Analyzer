from scapy.all import IP, TCP, ICMP, UDP, ARP, sniff, PcapWriter, rdpcap
import scapy.error
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse 
import sys 
import time
from datetime import datetime 
import keyboard 
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-c", "--count", type=int, help="Enter number of packets to capture")
parser.add_argument("-p", "--protocol", type=str, nargs='*', help="Filter for protocol")
parser.add_argument("-he", "--header", type=str, help="Extract and display the specified header.")
parser.add_argument("-src", "--source_ip", type=str, help="Filter for source ip address")
parser.add_argument("-dst", "--destination_ip", type=str, help="Filter for destination ip address")
parser.add_argument("-r", "--read_file", type=str, help="Read a Packet Capture file")
parser.add_argument("-w", "--write_file", type=str, help="Write to a Packet Capture file")
parser.add_argument("-flags", "--flags", type=str, help="Print out the packet flags")
args = parser.parse_args()

if (args.write_file != None) : 
    writer = PcapWriter(filename=args.write_file, sync=True, append=True)

protocols = {
    "IP": IP,
    "TCP": TCP,
    "ICMP": ICMP,
    "ARP": ARP,
    "UDP": UDP,
    "HTTP": HTTP
}

def flag_scan(packet) : 
    if keyboard.is_pressed('q') :
        print("Scan ended")
        sys.exit(0)
    time.sleep(0.1)

    try : 
        protocol = protocols[args.flags.upper()]

        if packet.haslayer(protocol) : 
            print(datetime.fromtimestamp(float(packet.time)), "Flags : ", list(packet[protocol].flags))
            
    except KeyError : 
        print("invalid protocol")

    except AttributeError : 
        print("Layer does not have flags")

def process(packet) : 
    if keyboard.is_pressed('q') :
        print("Scan ended")
        sys.exit(0)
    time.sleep(0.1)

    if args.write_file != None : 
        writer.write(packet)
     
    print(datetime.fromtimestamp(float(packet.time)), packet.summary())

             
def process2(packet) :
    print(datetime.fromtimestamp(float(packet.time)), packet.summary())

def ip_scan(packet) : 
    if keyboard.is_pressed('q') :
        print("Scan ended")
        sys.exit(0)
    time.sleep(0.1)

    try :
        if (packet.haslayer(IP)) : 
            if args.source_ip is not None and args.destination_ip is not None : 
                if (packet[IP].src == args.source_ip and packet[IP].dst == args.destination_ip) : 
                    print(datetime.fromtimestamp(float(packet.time)), packet.summary())

                    if args.write_file != None : 
                            writer.write(packet)

            elif args.source_ip is not None : 
                if (packet[IP].src == args.source_ip) : 
                    print(packet.summary())

                    if args.write_file != None : 
                            writer.write(packet)

            elif args.destination_ip is not None : 
                if (packet[IP].dst == args.destination_ip) : 
                    print(packet.summary())

                    if args.write_file != None : 
                            writer.write(packet)

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
            print(datetime.fromtimestamp(float(packet.time)), packet[header].show())

            if args.write_file != None : 
                    writer.write(packet)
    except scapy.error.Scapy_Exception : 
        print("Please enter valid protocol")
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
    if args.read_file != None : 
        try : 
            packets = rdpcap(args.read_file) 
            for pkt in packets : 
                print(pkt.time, pkt.summary())
        except scapy.error.Scapy_Exception : #the file does not exist 
            print("File does not exist")

    elif args.protocol != None : 
        protocol_filtered_scan(args.protocol)

    elif args.header != None : 
        if args.count != None : 
            sniff(prn=header_scan, store=False, count=args.count)
        else : 
            sniff(prn=header_scan, store=False)


    elif args.source_ip != None or args.destination_ip != None :
        if args.count != None : 
            sniff(prn=ip_scan, store=False, count=args.count)
        else : 
            sniff(prn=ip_scan, store=False)

    elif args.flags != None : 
        if args.count != None : 
            sniff(prn=flag_scan, store=False, count=args.count)
        else : 
            sniff(prn=flag_scan, store=False)

    else : 
        if args.count != None : 
            sniff(prn=process, store=False, count=args.count)
        else : 
            sniff(prn=process, store=False)

if __name__== "__main__" : 
    main()
    
