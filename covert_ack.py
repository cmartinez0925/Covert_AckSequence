#Author: Chris Martinez
#Course: Covert Channels
#Date:   July 13, 2024
#Description: Takes the original TCP Ack Seq Bounch method written by
#             Craig H. Rowland (1996) and coverts it into a 
#             modern python script using Scapy as its main 
#             driver for the packet manipulation and spoofing.


################################################################################
#IMPORTS - Gathering the troops
################################################################################
import argparse
import os
import sys
import time

from scapy.all import IP, TCP, send, sniff


################################################################################
#FUNCTIONS
################################################################################
#Author: Chris Martinez
#Date: July 13, 2024 
#Description: Parses packet and determines what message has been sent
def process_packets(pkt, port):
    try:
        if TCP in pkt and pkt[TCP].dport == port and pkt[TCP].flags == 'SA':
            #Lets decode this sucker from the sequence number
            msg = chr(pkt[TCP].ack - 1)
            print(f"Message: {msg}")
    except Exception as e:
        print(f"Error receiving message: {e}")


#Author: Chris Martinez
#Date: July 13, 2024 
#Description: Create a spoof IP/TCP packet with an embedded covert message
def send_message(src_ip, dst_ip, src_port, dst_port, message):
    WAIT_TIME = 1 #SECOND
    try:
        msg_in_bytes = message.encode()
        for byte in msg_in_bytes:
            #Create a TCP/IP pkt with the messge encoded in seq number
            ip = IP(src=src_ip, dst=dst_ip)
            tcp = TCP(sport=src_port, dport=dst_port, flags="S", seq=byte)

            #Send the packet
            send(ip/tcp)
            time.sleep(WAIT_TIME)
    except Exception as e:
        print(f"Error sending message: {e}")

#Author: Chris Martinez
#Date: July 13, 2024 
#Description: Listening for incoming packets 
def listen_for_packets(interface, port):
    FILTER = f"tcp and port {port}"
    sniff(iface=interface, 
          filter=FILTER, 
          prn=lambda pkt: process_packets(pkt, port))

################################################################################
#MAIN() SCRIPT
################################################################################
#Author: Chris Martinez
#Date: July 13, 2024
#Description: Main Script
def main():
    ############################################################################
    #TERMINAL ARGUMENTS SETUP - Get data from user via the terminal
    ############################################################################
    parser = argparse.ArgumentParser(description="Covert ACK")
    parser.add_argument("-s", "--src_ip", action="store", dest="src_ip", 
                        type=str, help="Source IP Address")
    parser.add_argument("-d", "--dest_ip", action="store", dest="dst_ip", 
                        type=str, help="Destination IP Address")
    parser.add_argument("-p", "--src_port", action="store", dest="src_port", 
                        type=int, help="Source Port")
    parser.add_argument("-t", "--dst_port", action="store", dest="dst_port", 
                        type=int, help="Destination Port")
    parser.add_argument("-i", "--iface", action="store", dest="iface", 
                        type=str, help="Interface to listen on")
    parser.add_argument("-r", "--receive", action="store_true", dest="receiver",
                        help="Run Script in Reciever Mode")
    parser.add_argument("-m", "--message", action="store", dest="message",
                        type=str, default="", help="Message to send")
    args = parser.parse_args()

    ############################################################################
    #CONSTANT VARIABLES - Thou shall not change
    ############################################################################
    VERSION = "1.0"
    SRC_ADDR = args.src_ip
    SRC_PORT = args.src_port
    DEST_ADDR = args.dst_ip
    DEST_PORT = args.dst_port
    IFACE = args.iface
    RECEIVING_DATA = args.receiver
    MESSAGE = args.message
    ROOT = 0
    
    #Lets get the party started
    print(f"Covert ACK {VERSION} (Christopher E. Martinez (cmart104@jh.edu)")
    print("Covert Channel Assignment 3 - Covert ACK using Scapy\n")

    #Only god can wield such power... him and root
    if os.geteuid() != ROOT:
        sys.exit("You need to be root to run this script.")

    ############################################################################
    #RECEIVING DATA - Do this if we are receiving the covert message
    ############################################################################
    if RECEIVING_DATA:
        print("Listening for IP/TCP traffic...")
        try:
            listen_for_packets(interface=IFACE, port=DEST_PORT)
        except Exception as e:
            print(f"Error during sniffing: {e}")

    ############################################################################
    #SENDING DATA - We do this if we are trying to send the covert message
    ############################################################################
    else:
        try:
            send_message(SRC_ADDR, DEST_ADDR, SRC_PORT, DEST_PORT, MESSAGE)
        except Exception as e:
            sys.exit(f"Error sending message: {e}")

if __name__ == '__main__':
    main()
