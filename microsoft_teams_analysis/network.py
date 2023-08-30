import pyshark
import socket

file_path = 'full.pcapng'
cap = pyshark.FileCapture(file_path, display_filter='ip')

ip_destinations = set()
ip_to_domain = {}

print("Number of packets: ", len(list(cap)))
for pkt in cap:
    if 'IP' in pkt:
        ip_destinations.add(pkt.ip.dst)

        if hasattr(pkt, 'dns') and pkt.dns.qry_name:
            domain = pkt.dns.qry_name
            ip_to_domain[pkt.ip.dst] = domain


for ip in ip_destinations:
    if ip not in ip_to_domain:
        try:
            domain_name = socket.gethostbyaddr(ip)[0]
            ip_to_domain[ip] = domain_name
        except socket.herror:
            pass

for ip, domain in ip_to_domain.items():
    print(f"{ip} -> {domain}")

# Check for NAT Traversal Techniques like STUN
stun_packets = pyshark.FileCapture(file_path, display_filter='stun')
if len(list(stun_packets)) > 0:
    print("\nNumber of STUN packets: ", len(list(stun_packets)))
else:
    print("\nNo STUN packets were found")

def is_ip_in_range(ip_parts, start, end):
    return all(s <= ip <= e for s, ip, e in zip(start, ip_parts, end))

private_ips = [
    ((10, 0, 0, 0), (10, 255, 255, 255)),
    ((172, 16, 0, 0), (172, 31, 255, 255)),
    ((192, 168, 0, 0), (192, 168, 255, 255))
]

private_count = 0
public_count = 0
for ip in ip_destinations:
    parts = tuple(map(int, ip.split('.')))
    is_private = False
    for range_start, range_end in private_ips:
        if is_ip_in_range(parts, range_start, range_end):
            is_private = True
            break
    if is_private:
        private_count += 1
    else:
        public_count += 1


print("\nAnalysis:")
print("\nPrivate count:", private_count)
print("\nPublic count:", public_count)