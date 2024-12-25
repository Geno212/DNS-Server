import socket, time
from dns_utils import parse_query, build_response, build_nxdomain, RECORD_TYPES, log, forward_query

ROOT_DATABASE = {
    "com": {"type":"NS","ttl":300,"value":"ns.com.tld."},
    "org": {"type":"NS","ttl":300,"value":"ns.org.tld."}
}

TLD_SERVER = ("192.168.1.19", 5301)

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

def find_record(domain, qtype):
    # Check if in cache
    cached = get_from_cache(domain, qtype)
    if cached:
        return cached

    parts = domain.split(".")
    if len(parts) < 2:
        return None
    tld = parts[-1]
    if tld in ROOT_DATABASE:
        # Forward query to TLD
        records = forward_query(domain, qtype, TLD_SERVER)
        if records:
            put_in_cache(domain, qtype, records)
        return records
    return None

def start_root_server(ip="192.168.1.19", port=53):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    log(f"Root DNS server started on {ip}:{port}")

    while True:
        data, addr = sock.recvfrom(512)
        transaction_id, domain, qtype = parse_query(data)
        log(f"Root server query: {domain}, type: {RECORD_TYPES.get(qtype,'?')}")

        records = find_record(domain, qtype)
        if records:
            response = build_response(transaction_id, domain, qtype, records)
        else:
            response = build_nxdomain(transaction_id, domain, qtype)
        sock.sendto(response, addr)

if __name__ == "__main__":
    start_root_server()
