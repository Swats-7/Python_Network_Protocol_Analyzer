from scapy.all import IP, TCP, ICMP, UDP, ARP, HTTP, sniff 
import sys 
import time
from datetime import datetime 
import keyboard 
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-c", "--count", type=int, help="Enter number of packets to capture")
parser.add_argument("-p", "--protocol", type=str, nargs='*', help="Filter for protocol")
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

    #checking for filters 
    if args.protocol != None : 
        eligible = True 
        for filter in args.protocol : 
            if (filter not in protocols) : 
                eligible = False 

        for filter in args.protocol :
            filter = "".join(char for char in filter if char.isalpha()).upper() 
            layer = protocols[filter]
            if packet.haslayer(layer) == False :
                eligible = False

        if eligible == True : 
            print(packet.summary()) 

    else : 
        print(packet.summary())

             
def process2(packet) :
    print(packet.summary())


def main() :
    while True : 
        sniff(prn=process, store=False)

    

if __name__== "__main__" : 
    main()
