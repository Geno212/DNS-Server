import socket, time
from dns_utils import parse_query, build_response, build_nxdomain, RECORD_TYPES, log, forward_query, parse_nxdomain_response

ROOT_DATABASE = {
    "com": {"type":"NS","ttl":300,"value":"ns.com.tld."},
    "org": {"type":"NS","ttl":300,"value":"ns.org.tld."},
    "4.1.168.192.in-addr.arpa": {"type": "PTR", "ttl": 300, "value": "Our-Networks-DNS-Server-root-dns.local"}
}

TLD_SERVER = ("192.168.1.4", 5301)

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
    # Check if in cache
    cached = get_from_cache(domain, qtype)
    if cached:
        return cached

    log(f"Root server handling domain '{domain}' with qtype {qtype}")
    if domain in ROOT_DATABASE:
        log(f"Found {domain} in ROOT_DATABASE")
        return [ROOT_DATABASE[domain]]

    parts = domain.split(".")
    log(f"Domain parts: {parts}")
    if len(parts) < 2:
        log("Domain has less than 2 parts, returning None")
        return None
    tld = parts[-1]
    log(f"Extracted TLD: {tld}")
    if tld in ROOT_DATABASE:
        log(f"TLD {tld} found in ROOT_DATABASE, forwarding query to TLD server")
        # Forward query to TLD
        records = forward_query(domain, qtype, TLD_SERVER, transaction_id)
        if records:
            log(f"Received records from TLD server: {records}")
            put_in_cache(domain, qtype, records)
        else:
            log(f"No records received from TLD server for domain {domain}")
        return records
    else:
        log(f"TLD {tld} not found in ROOT_DATABASE")
    return None

def start_root_server(ip="192.168.1.4", port=53):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    log(f"Root DNS server started on {ip}:{port}")

    while True:
        data, addr = sock.recvfrom(512)
        transaction_id, domain, qtype = parse_query(data)
        qtype_str = RECORD_TYPES.get(qtype,'?')
        log(f"Root server received query from {addr}: {domain}, type: {qtype_str}, transaction ID: {transaction_id}")

        records = find_record(domain, qtype, transaction_id)
        if records:
            response = build_response(transaction_id, domain, qtype, records)
        else:
            response = build_nxdomain(transaction_id, domain, qtype)
            nx_transaction_id, nx_domain, nx_qtype = parse_nxdomain_response(response)
            log(f"ROOT server generated NXDOMAIN response for Transaction ID: {nx_transaction_id}, Domain: {nx_domain}, Type: {nx_qtype}")
        sock.sendto(response, addr)
        log(f"Root server sent response to {addr} for transaction ID {transaction_id}")

if __name__ == "__main__":
    start_root_server()