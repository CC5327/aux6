from memcached import Memcached
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.ntp import NTPPrivate
from scapy.layers.dns import DNS, DNSQR


def send_memcached(ip, port):
    print(f"memcached: {ip}:{port}")
    pkt = IP(dst=ip) / UDP(sport=54321, dport=port) / \
        Memcached(msg="stats\r\n") # The memcached queries must finish in a line break
    print(f"Sending: {pkt.summary()}")
    ans = sr1(pkt, verbose=1)
    print(f"received:")
    ans.show()


def send_dns(ip, port):
    print(f"dns: {ip}:{port}")
    pkt = IP(dst=ip) / UDP(sport=54323, dport=port) / DNS(rd=1, id=12345,  qd=DNSQR(
        qtype=1, qname="lab4.cc5312.xor.cl"))  # qtype=1 is A and DNS Request ID is 12345
    print(f"Sending: {pkt.summary()}")
    # ANS is like  IP(src=ip, dst=<myip>) / UDP(sport=port, dport=54323) / DNS(rd=1, qd=DNSQR(qtype=1, qname="lab4.cc5312.xor.cl") an=[<RRs received>]) # 1 is A
    ans = sr1(pkt, verbose=1)
    print(f"received:")
    ans.show()


def send_ntp(ip, port):
    print(f"ntp: {ip}:{port}")
    pkt = IP(dst=ip) / UDP(sport=54322, dport=port) / NTPPrivate(version=3,
                                                                 mode=7, implementation=3, request_code=42)  # 42 is mon_getlist_1
    print(f"Sending: {pkt.summary()}")
    ans = sr1(pkt, verbose=1)
    print(f"received:")
    ans.show()


TEST_IP = "172.17.69.106"

DNS_PORT = 53
NTP_PORT = 123
MEMCACHED_PORT = 11211

if __name__ == "__main__":
    send_memcached(TEST_IP, MEMCACHED_PORT)
    send_dns(TEST_IP, DNS_PORT)
    send_ntp(TEST_IP, NTP_PORT)
