import pyshark

def analyze_dns(capture_file):
    cap = pyshark.FileCapture(capture_file, display_filter='dns')

    domain_names = set()
    authoritative_servers = set()
    dns_request_types = {}
    ip_families = {"IPv4": 0, "IPv6": 0}
    additional_records = 0

    for packet in cap:
        if hasattr(packet, 'dns'):
            if hasattr(packet.dns, 'qry_name'):
                domain_names.add(packet.dns.qry_name)
            if hasattr(packet.dns, 'type'):
                dns_request_types[packet.dns.type] = dns_request_types.get(packet.dns.type, 0) + 1
            
            if packet.dns.qry_type == '1':
                ip_families["IPv4"] += 1
            elif packet.dns.qry_type == '28':
                ip_families["IPv6"] += 1
            
            # Authority Records
            if hasattr(packet.dns, 'ns'):
                authoritative_servers.add(packet.dns.ns)
            
            # Additional Records
            if hasattr(packet.dns, 'additional_count') and int(packet.dns.additional_count) > 0:
                additional_records += int(packet.dns.additional_count)


    print(domain_names)
    print(authoritative_servers)
    print(dns_request_types)
    print(ip_families)
    print(additional_records)

# Test
analyze_dns('full.pcapng')
