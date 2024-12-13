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
    ]
}

def find_record(domain, qtype):
    # Return records of requested type if available
    qtype_str = RECORD_TYPES.get(qtype, None)
    if domain in AUTH_DATABASE:
        if qtype_str:
            filtered = [r for r in AUTH_DATABASE[domain] if r["type"] == qtype_str]
            if filtered:
                return filtered
        # If no direct match, maybe return something else or NXDOMAIN
        return None
    return None

def start_auth_server(ip="127.0.0.1", port=5302):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    log(f"Authoritative DNS server started on {ip}:{port}")

    while True:
        data, addr = sock.recvfrom(512)
        transaction_id, domain, qtype = parse_query(data)
        log(f"Auth server query: {domain}, type: {RECORD_TYPES.get(qtype,'?')}")

        records = find_record(domain, qtype)
        if records:
            response = build_response(transaction_id, domain, qtype, records)
        else:
            response = build_nxdomain(transaction_id, domain, qtype)
        sock.sendto(response, addr)

if __name__ == "__main__":
    start_auth_server()
