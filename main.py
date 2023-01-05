import netfilterqueue
import subprocess
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser()
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument('-l', '--local', action='store', help='Use in Local Mode')
    scope.add_argument('-r', '--remote', action='store', help='Use in Remote Mode')

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('-d', '--drop', action='store', help='Drop Packets')
    mode.add_argument('-f', '--forward', action='store', help='Forward Packets')
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
try:
    queue.run()
except KeyboardInterrupt:
    print('Reseting IP Table...')
    subprocess.call('iptables --flush')
    print('Exiting...')
