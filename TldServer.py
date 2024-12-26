import socket, time
from dns_utils import parse_query, build_response, build_nxdomain, RECORD_TYPES, log, forward_query

TLD_DATABASE = {
    "com": {
        "google": {"type": "NS", "ttl": 300, "value": "ns.google.auth."},
        "facebook": {"type": "NS", "ttl": 300, "value": "ns.facebook.auth."}
    },
    "org": {
        "wikipedia": {"type": "NS", "ttl": 300, "value": "ns.wikipedia.auth."}
    },
    "2.10.20.172.in-addr.arpa": {"type": "PTR", "ttl": 300, "value": "tld-dns.local"}
}

AUTH_SERVER = ("172.20.10.2", 5302)

CACHE = {}  # {(domain, qtype_str): (records, expiration_time)}

def get_from_cache(domain, qtype):
    qtype_str = RECORD_TYPES.get(qtype, None)
    if qtype_str is None:
        return None
    now = time.time()
    key = (domain, qtype_str)
    if key in CACHE:
        records, exp = CACHE[key]
        if now < exp:
            log(f"Returning cached result for {domain}, type={qtype_str}")
            return records
        else:
            del CACHE[key]
    return None

def put_in_cache(domain, qtype, records):
    qtype_str = RECORD_TYPES.get(qtype, None)
    if qtype_str and records:
        ttl = records[0].get("ttl", 300)
        expiration = time.time() + ttl
        CACHE[(domain, qtype_str)] = (records, expiration)

def find_record(domain, qtype, transaction_id):
    # Check cache first
    cached = get_from_cache(domain, qtype)
    if cached:
        return cached

    log(f"TLD server handling domain '{domain}' with qtype {qtype}")
    if domain in TLD_DATABASE:
        log(f"Found {domain} in TLD_DATABASE")
        return [TLD_DATABASE[domain]]

    parts = domain.split(".")
    log(f"Domain parts: {parts}")
    if len(parts) < 2:
        log("Domain has less than 2 parts, returning None")
        return None
    sld, tld = parts[-2], parts[-1]
    log(f"Extracted SLD: {sld}, TLD: {tld}")
    if tld in TLD_DATABASE and sld in TLD_DATABASE[tld]:
        log(f"Found SLD {sld} in TLD_DATABASE under TLD {tld}")
        # We have NS record, forward query to Auth
        auth_records = forward_query(domain, qtype, AUTH_SERVER, transaction_id)
        if auth_records:
            log(f"Received records from Auth server: {auth_records}")
            put_in_cache(domain, qtype, auth_records)
            return auth_records
        else:
            log(f"No direct record from Auth server for domain {domain}, using NS record as fallback")
            ns_rec = [TLD_DATABASE[tld][sld]]
            put_in_cache(domain, qtype, ns_rec)
            return ns_rec
    else:
        log(f"SLD {sld} not found in TLD_DATABASE under TLD {tld}")
    return None

def start_tld_server(ip="172.20.10.2", port=5301):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    log(f"TLD DNS server started on {ip}:{port}")

    while True:
        data, addr = sock.recvfrom(512)
        transaction_id, domain, qtype = parse_query(data)
        qtype_str = RECORD_TYPES.get(qtype, '?')
        log(f"TLD server received query from {addr}: {domain}, type: {qtype_str}, transaction ID: {transaction_id}")

        records = find_record(domain, qtype, transaction_id)
        if records:
            response = build_response(transaction_id, domain, qtype, records)
        else:
            response = build_nxdomain(transaction_id, domain, qtype)
        sock.sendto(response, addr)
        log(f"TLD server sent response to {addr} for transaction ID {transaction_id}")

if __name__ == "__main__":
    start_tld_server()