from scapy.all import *
import os
import argparse

PROTOCOL_VALUES = { "icmp":{"type" : ICMP , "length" : 60 , "payload" : b"abcdefghijklmnopqrstuvwabcdefghi"}}
LOCALHOST = "127.0.0.1"

# Detect annomalies in ICMP Packets
def icmpTunnelingDetection(packets):

             
    for packet in packets:

        for protocol, values in PROTOCOL_VALUES.items():
                
            # Annomaly by packet's length
            if(packet.len > values["length"]):
                print("Length Anomally!\n\t{}\n\tLength: {} instead of: {}\n\tSrc: {}\n\tDst: {}\n\tPayload: {}".format(packet.summary(),
                                                                                                                        packet.len,
                                                                                                                      values["length"],
                                                                                                                      packet.payload.src,
                                                                                                                      packet.payload.dst,
                                                                                                                      packet.payload.load))

            # Annomaly by packet's payload
            elif(packet.payload.load != values["payload"]):
                print("Payload Anomally!\n\t{}\n\tLength: {}\n\tSrc: {}\n\tDst: {}\n\tPayload: {}".format(packet.summary(),
                                                                                                          packet.len,
                                                                                                        packet.payload.src,
                                                                                                        packet.payload.dst,
                                                                                                        packet.payload.load))
            # Good packet
            else:
                print("GOOD PACKET!!\n\t{}\n\tLength: {}\n\tSrc: {}\n\tDst: {}\n\tPayload: {}".format(packet.summary(),
                                                                                                    packet.len,
                                                                                                    packet.payload.src,
                                                                                                    packet.payload.dst,
                                                                                                    packet.payload.load))

# Send ICMP Packet with payload
def sendICMPPacket():

    ip = input('# Enter destination IP address: ')
    command = input('# Enter payload: ')
    
    pinger = IP(dst=ip)/ICMP(id=0x0001, seq=0x1)/command
    #send(pinger)
    send_rec = sr(pinger)
    var = send_rec[0][Raw].load.decode('utf-8')
    print(var)
    
def main():
    parser = argparse.ArgumentParser(description='ICMP Tunneling Detection')
    parser.add_argument('--sniff', help='Sniff And Analyze ICMP Packets' , action='store_true')
    parser.add_argument('--send', help='Send Created ICMP Packet' , action='store_true')
    args = parser.parse_args()

    if args.sniff:
        try:
            sniff(filter="icmp",prn=icmpTunnelingDetection)
        except:
            print("Something wrong in sniffing packets")
    elif args.send:
            try:
                sendICMPPacket()
            except:
                print("Could not send packet")
    else:
        print("Missing argument ( --sniff or --send )...")

if __name__ == "__main__":
    main()
