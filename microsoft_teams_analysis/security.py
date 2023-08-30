import pyshark

filename = 'full.pcapng'
cap = pyshark.FileCapture(filename)

doh_traffic = 0
dot_traffic = 0
dnssec_traffic = 0
standard_dns_traffic = 0

for packet in cap:
    if hasattr(packet, 'tcp') and packet.tcp.port == '853':
        dot_traffic += 1

    elif hasattr(packet, 'http') and ('application/dns-message' in str(packet.layers)):
        doh_traffic += 1

    elif hasattr(packet, 'dns'):
        standard_dns_traffic += 1
        if 'dnssec' in str(packet.layers):
            dnssec_traffic += 1


print(f"Total DNS over TLS (DoT) traffic: {dot_traffic}")
print(f"Total DNS over HTTPS (DoH) traffic: {doh_traffic}")
print(f"Total Standard DNS traffic: {standard_dns_traffic}")
print(f"Total DNSSEC traffic: {dnssec_traffic}")
