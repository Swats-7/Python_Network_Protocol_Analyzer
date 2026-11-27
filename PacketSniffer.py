from scapy.all import IP, TCP, ICMP, UDP, ARP, sniff, PcapWriter, rdpcap
import scapy.error
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse 
import sys 
import time
from datetime import datetime 
import keyboard 
import argparse

"""
These are all the command line arguments that can be passed to the program 
to employ its various functionalities. The help line displays what the particular flag does 
"""
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

"""
This creates a writer object to write to the packet capture file specified by the user. 
"""
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

"""
The first type of scan is the flag scan. 
It takes as a parameter a scapy packet and checks if the CLI parameter supplied with the -flags option 
is a valid protocol that has flags. 
"""
def flag_scan(packet) : 
    if keyboard.is_pressed('q') :
        print("-"*150)
        print("Scan ended")
        print(datetime.now())
        sys.exit(0)


    try : 
        protocol = protocols[args.flags.upper()]

        if packet.haslayer(protocol) : 
            print(datetime.fromtimestamp(float(packet.time)), "Flags : ", list(packet[protocol].flags))
            
    except KeyError : 
        print("invalid protocol")

    except AttributeError : 
        print("Layer does not have flags")

"""
This scan is a simple scan. 
It takes as a parameter a scapy packet and simply prints the summary of the packet along with 
the time of when it was recieved or sent out.
"""
def simple_scan(packet) : 
    if keyboard.is_pressed('q') :
        print("-"*150)
        print("Scan ended")
        print(datetime.now())
        sys.exit(0)


    if args.write_file != None : 
        writer.write(packet)
     
    print(datetime.fromtimestamp(float(packet.time)), packet.summary())

"""
This scan takes effect if the user specifies a source or destination IP addres or both 
to analyze data to and from. The source and destination ip addresses are parts of the header of the IP layer
and hence the scan first checks if the packet has an IP layer, then checking if the source or destination ip or both
match the ones specified.
"""
def ip_scan(packet) : 
    if keyboard.is_pressed('q') :
        print("-"*150)
        print("Scan ended")
        print(datetime.now())
        sys.exit(0)


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

"""
This scan checks if the paacket has the protocol layer which was passed as a parameter in the 
-he flag. If it does, the header of the packet is printed out. 
"""
def header_scan(packet) :
    if keyboard.is_pressed('q') :
        print("-"*150)
        print("Scan ended")
        print(datetime.now())
        sys.exit(0)

    try : 
        header = protocols[args.header.upper()]
        if packet.haslayer(header) : 
            print(datetime.fromtimestamp(float(packet.time)), packet[header].show())

            if args.write_file != None : 
                    writer.write(packet)
    except scapy.error.Scapy_Exception : 
        print("Please enter valid protocol")
        sys.exit(0)

"""
Many protocols can be specified at a time so this scan first creates a string to be
passed as parameter while capturing packets with the following protocols. 
Once the string is created, it calls the simple scan with the filter. 
"""
def protocol_filtered_scan(protocol) :
    list_of_filters = [] 
    for filter in args.protocol :
        filter = "".join(char for char in filter if char.isalpha()).lower() 
        list_of_filters.append(filter)
        filters = " or ".join(list_of_filters)
        print(filters)

    if (args.count != None) : 
        try :
            sniff(prn=simple_scan, count = args.count, filter=filters, store=False)

        except scapy.error.Scapy_Exception : #if the filter entered is incorrect
            print("Please choose a valid filter")
            sys.exit(0)

    else :
        try :
            sniff(prn=simple_scan, filter=filters, store=False)

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
            sniff(prn=simple_scan, store=False, count=args.count)
        else : 
            sniff(prn=simple_scan, store=False)

if __name__== "__main__" : 
    print("Welcome to Swat's Sniffer")
    print(r"""
           / \      _-'
         _/|  \-''- _ /
    __-' { |          \
        /             \
        /       "o.  |o }
        |            \ ;
                      ',
           \_         __\
            ''-_    \.//
               / '-____'
              /
            _'
          _-'
    """)
    print("Packet Sniffing started")
    print(datetime.now())
    print("-"*150)
    main()
    
