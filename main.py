import netfilterqueue
import subprocess
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--local', help='Use in Local Mode')
    parser.add_argument('-r', '--remote', help='Use in Remote Mode')
    parser.add_argument('-d', '--drop', help='Drop Packets')
    parser.add_argument('-f', '--forward', help='Forward Packets')
    return parser.parse_args()

def process_packet(packet):
    print(packet)
    if options.drop:
        packet.drop()
    elif options.forward:
        packet.accept()


options = parse_arguments()

if options.local:
    subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
    subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)
elif options.remote:
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
