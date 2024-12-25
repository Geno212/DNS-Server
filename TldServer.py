import socket, time
from dns_utils import parse_query, build_response, build_nxdomain, RECORD_TYPES, log, forward_query

TLD_DATABASE = {
    "com": {
        "google": {"type": "NS", "ttl": 300, "value": "ns.google.auth."},
        "facebook": {"type": "NS", "ttl": 300, "value": "ns.facebook.auth."}
    },
    "org": {
        "wikipedia": {"type": "NS", "ttl": 300, "value": "ns.wikipedia.auth."}
    }
}

AUTH_SERVER = ("192.168.1.19", 5302)

# Cache structure: {(domain, qtype_str): (records, expiration_time)}
CACHE = {}


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


def find_record(domain, qtype):
    # Check cache first
    cached = get_from_cache(domain, qtype)
    if cached:
        return cached

    parts = domain.split(".")
    if len(parts) < 2:
        return None
    sld, tld = parts[-2], parts[-1]
    if tld in TLD_DATABASE and sld in TLD_DATABASE[tld]:
        # We have NS record, forward query to Auth
        auth_records = forward_query(domain, qtype, AUTH_SERVER)
        if auth_records:
            put_in_cache(domain, qtype, auth_records)
            return auth_records
        else:
            # No direct record from auth, try NS fallback
            ns_rec = [TLD_DATABASE[tld][sld]]
            put_in_cache(domain, qtype, ns_rec)
            return ns_rec
    return None


def start_tld_server(ip="192.168.1.19", port=5301):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    log(f"TLD DNS server started on {ip}:{port}")

    while True:
        data, addr = sock.recvfrom(512)
        transaction_id, domain, qtype = parse_query(data)
        log(f"TLD server query: {domain}, type: {RECORD_TYPES.get(qtype, '?')}")

        records = find_record(domain, qtype)
        if records:
            response = build_response(transaction_id, domain, qtype, records)
        else:
            response = build_nxdomain(transaction_id, domain, qtype)
        sock.sendto(response, addr)


if __name__ == "__main__":
    start_tld_server()
