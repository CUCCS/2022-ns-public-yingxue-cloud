#! /usr/bin/python

from scapy.all import * 
import argparse

# TCP connect
def TCP_Connect(ip,port):
    TCP_Connect_resp = sr1(IP(dst=ip)/TCP(sport=8888,dport=port,flags="S"),timeout=3)

    if(TCP_Connect_resp is None):
        print("Filtered")
    elif(TCP_Connect_resp.haslayer(TCP)):
        if(TCP_Connect_resp.getlayer(TCP).flags == 0x12):  # ACK, SYN
            send_rst = sr(IP(dst=ip)/TCP(sport=8888,dport=port,flags="AR"),timeout=3)
            print("Open")
        elif(TCP_Connect_resp.getlayer(TCP).flags == 0x14):  # RST, ACK
            print("Closed")
    elif(TCP_Connect_resp.haslayer(ICMP)):
        if(int(TCP_Connect_resp.getlayer(ICMP).type) == 3 and int(TCP_Connect_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print("Filtered") 


def TCP_Stealth(ip,port):
    TCP_Stealth_resp = sr1(IP(dst=ip)/TCP(dport=port,flags="S"),timeout=3)
    
    if(TCP_Stealth_resp is None):
        print("Filtered")
    elif(TCP_Stealth_resp.haslayer(TCP)):
        if(TCP_Stealth_resp.getlayer(TCP).flags == 0x12):  # ACK, SYN
            send_rst = sr(IP(dst=ip)/TCP(dport=port,flags="R"),timeout=3)
            print("Open")
        elif(TCP_Stealth_resp.getlayer(TCP).flags == 0x14):  # RST, ACK
            print("Closed")
    elif(TCP_Stealth_resp.haslayer(ICMP)):
        if(int(TCP_Stealth_resp.getlayer(ICMP).type) == 3 and int(TCP_Stealth_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print("Filtered")        

def TCP_Xmas(ip,port):
    TCP_Xmas_resp = sr1(IP(dst=ip)/TCP(dport=port,flags="FPU"),timeout=3)
    
    if(TCP_Xmas_resp is None):
        print("Open or Filtered")
    elif(TCP_Xmas_resp.haslayer(TCP)):
        if(TCP_Xmas_resp.getlayer(TCP).flags == 0x14):  # RST, ACK
            print("Closed")
    elif(TCP_Xmas_resp.haslayer(ICMP)):
        if(int(TCP_Xmas_resp.getlayer(ICMP).type) == 3 and int(TCP_Xmas_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print("Filtered")

def TCP_Fin(ip,port):
    TCP_Fin_resp = sr1(IP(dst=ip)/TCP(dport=port,flags="F"),timeout=3)
    
    if(TCP_Fin_resp is None):
        print("Open or Filtered")
    elif(TCP_Fin_resp.haslayer(TCP)):
        if(TCP_Fin_resp.getlayer(TCP).flags == 0x14):  # RST, ACK
            print("Closed")
    elif(TCP_Fin_resp.haslayer(ICMP)):
        if(int(TCP_Fin_resp.getlayer(ICMP).type) == 3 and int(TCP_Fin_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print("Filtered")

def TCP_Null(ip,port):
    TCP_Null_resp = sr1(IP(dst=ip)/TCP(dport=port,flags=""),timeout=3)
    
    if(TCP_Null_resp is None):
        print("Open or Filtered")
    elif(TCP_Null_resp.haslayer(TCP)):
        if(TCP_Null_resp.getlayer(TCP).flags == 0x14):  # RST, ACK
            print("Closed")
    elif(TCP_Null_resp.haslayer(ICMP)):
        if(int(TCP_Null_resp.getlayer(ICMP).type) == 3 and int(TCP_Null_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print("Filtered")

def UDP_Scan(ip,port):
    UDP_Scan_resp = sr1(IP(dst=ip)/UDP(dport=port),timeout=3)
    if(UDP_Scan_resp is None ):
        print("Open or Filtered")
    elif(UDP_Scan_resp.haslayer(UDP)):
        print("Open")
    elif(UDP_Scan_resp.haslayer(ICMP)):
        if(int(UDP_Scan_resp.getlayer(ICMP).type) == 3 and int(UDP_Scan_resp.getlayer(ICMP).code) == 3):
            print("Filter or Closed")
        elif(int(UDP_Scan_resp.getlayer(ICMP).type) == 3 and int(UDP_Scan_resp.getlayer(ICMP).code) == [1,2,9,10,13]):
            print("Filtered")
        elif(UDP_Scan_resp.haslayer(IP) and UDP_Scan_resp.getlayer(IP).proto == IP_PROTOS.udp):
            print("Open")


parser = argparse.ArgumentParser(
        description = "This is a scriptcode that scans the status of destination port of the destination host")
parser.add_argument('-s', '--scantype', type=str, help='methods to scan the destination port', required=True,
                    choices=['TCP_Connect', 'TCP_Stealth', 'TCP_Xmas', 'TCP_Fin', 'TCP_Null', 'UDP_Scan'])
parser.add_argument('-i', '--dstip', type=str,
                    help='IP address of the destination host', required=True)
parser.add_argument('-p', '--dstport', type=int,
                    help='destination port number', required=True)
args = parser.parse_args()

if __name__ == '__main__':
    try:
        print(args.scantype + "scanning...")
        if(args.scantype == 'TCP_Connect'):
            TCP_Connect(args.dstip, args.dstport)
        elif(args.scantype == 'TCP_Stealth'):
            TCP_Stealth(args.dstip, args.dstport)
        elif(args.scantype == 'TCP_Xmas'):
            TCP_Xmas(args.dstip, args.dstport)
        elif(args.scantype == 'TCP_Fin'):
            TCP_Fin(args.dstip, args.dstport)
        elif(args.scantype == 'TCP_Null'):
            TCP_Null(args.dstip, args.dstport)
        elif(args.scantype == 'UDP_Scan'):
            UDP_Scan(args.dstip, args.dstport)
    except Exception as e:
        print(e)
