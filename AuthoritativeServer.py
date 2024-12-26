import socket
from dns_utils import parse_query, build_response, build_nxdomain, RECORD_TYPES, log

AUTH_DATABASE = {
    "google.com": [
        {"type":"A","ttl":300,"value":"142.250.190.46"},
        {"type":"AAAA","ttl":300,"value":"2607:f8b0:4005:805::200e"},
        {"type":"MX","ttl":300,"value":"mail.google.com","preference":10},
        {"type":"NS","ttl":300,"value":"ns.google.com"}
    ],
    "facebook.com": [
        {"type":"A","ttl":300,"value":"157.240.221.35"},
        {"type":"MX","ttl":300,"value":"mail.facebook.com","preference":20},
        {"type":"NS","ttl":300,"value":"ns.facebook.com"}
    ],
    "wikipedia.org": [
        {"type":"A","ttl":300,"value":"91.198.174.192"},
        {"type":"AAAA","ttl":300,"value":"2620:0:862:ed1a::1"},
        {"type":"NS","ttl":300,"value":"ns1.wikimedia.org"}
    ],
    "2.10.20.172.in-addr.arpa": [
        {"type": "PTR", "ttl": 300, "value": "auth-dns.local"}
    ]
}

def find_record(domain, qtype):
    qtype_str = RECORD_TYPES.get(qtype, None)
    log(f"Authoritative server handling domain '{domain}' with qtype {qtype}")
    if domain in AUTH_DATABASE:
        log(f"Found {domain} in AUTH_DATABASE")
        if qtype_str:
            filtered = [r for r in AUTH_DATABASE[domain] if r["type"] == qtype_str]
            if filtered:
                log(f"Found matching records: {filtered}")
                return filtered
            else:
                log(f"No records of type {qtype_str} for domain {domain}")
        # If no direct match, maybe return something else or NXDOMAIN
        return None
    else:
        log(f"Domain {domain} not found in AUTH_DATABASE")
    return None

def start_auth_server(ip="172.20.10.2", port=5302):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    log(f"Authoritative DNS server started on {ip}:{port}")

    while True:
        data, addr = sock.recvfrom(512)
        transaction_id, domain, qtype = parse_query(data)
        qtype_str = RECORD_TYPES.get(qtype,'?')
        log(f"Auth server received query from {addr}: {domain}, type: {qtype_str}, transaction ID: {transaction_id}")

        records = find_record(domain, qtype)
        if records:
            response = build_response(transaction_id, domain, qtype, records)
        else:
            response = build_nxdomain(transaction_id, domain, qtype)
        sock.sendto(response, addr)
        log(f"Auth server sent response to {addr} for transaction ID {transaction_id}")

if __name__ == "__main__":
    start_auth_server()