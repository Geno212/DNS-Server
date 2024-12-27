import socket
from dns_utils import parse_query, build_response, build_nxdomain, RECORD_TYPES, log, parse_nxdomain_response

AUTH_DATABASE = {
    "google.com": [
        {"type":"A","ttl":300,"value":"172.217.18.46"},
        {"type":"AAAA","ttl":300,"value":"2a00:1450:4006:801::200e"},
        {"type":"MX","ttl":300,"value":"smtp.google.com","preference":10},
        {"type":"NS","ttl":300,"value":"ns1.google.com"},
        {"type": "CNAME", "ttl": 300, "value": "googlemail.l.google.com."}
    ],
    "facebook.com": [
        {"type":"A","ttl":300,"value":"102.132.103.35"},
        {"type":"MX","ttl":300,"value":"smtpin.vvv.facebook.com","preference":20},
        {"type":"NS","ttl":300,"value":"a.ns.facebook.com"},
        {"type": "CNAME", "ttl": 300, "value": "gstar.c10r.facebook.com"}
    ],
    "wikipedia.org": [
        {"type":"A","ttl":300,"value":"185.15.58.224"},
        {"type":"AAAA","ttl":300,"value":"2a02:ec80:600:ed1a::1"},
        {"type":"NS","ttl":300,"value":"ns1.wikimedia.org"},
        {"type": "CNAME", "ttl": 300, "value": "dyna.wikimedia.org"}
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

def start_auth_server(ip="192.168.1.4", port=5302):
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
            nx_transaction_id, nx_domain, nx_qtype = parse_nxdomain_response(response)
            log(f"Auth server generated NXDOMAIN response for Transaction ID: {nx_transaction_id}, Domain: {nx_domain}, Type: {nx_qtype}")
        sock.sendto(response, addr)
        log(f"Auth server sent response to {addr} for transaction ID {transaction_id}")

if __name__ == "__main__":
    start_auth_server()