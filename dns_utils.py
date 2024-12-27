import socket
import struct
import datetime
import random


transaction_id=0

# dns_utils.py
RECORD_TYPES = {
    1: "A",
    28: "AAAA",
    15: "MX",
    2: "NS",
    12: "PTR",
    5: "CNAME"  # Added CNAME support
}

def log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("dns_server.log", "a") as f:
        f.write(f"{timestamp} - {message}\n")
    print(f"{timestamp} - {message}")

def parse_query(data):
    transaction_id = struct.unpack(">H", data[:2])[0]
    flags = data[2:4]
    qdcount = struct.unpack(">H", data[4:6])[0]
    qname_end = data.find(b"\x00", 12)
    qname = data[12:qname_end]
    qtype, qclass = struct.unpack(">HH", data[qname_end + 1:qname_end + 5])

    domain_parts = []
    temp = qname
    while temp:
        length = temp[0]
        part = temp[1:1 + length].decode()
        domain_parts.append(part)
        temp = temp[1 + length:]
    domain = ".".join(domain_parts)
    return transaction_id, domain, qtype

def encode_domain_name(domain):
    encoded = b""
    for part in domain.strip('.').split('.'):
        encoded += bytes([len(part)]) + part.encode()
    encoded += b"\x00"
    return encoded

def build_response(transaction_id, domain, qtype, records):
    response = struct.pack(">H", transaction_id)
    response += b"\x81\x80"  # flags: response, no error
    response += struct.pack(">HHHH", 1, len(records), 0, 0)  # QD=1, AN=records, NS=0, AR=0

    # Question
    response += encode_domain_name(domain)
    response += struct.pack(">HH", qtype, 1)

    for r in records:
        response += b"\xc0\x0c"  # name pointer to question
        rt = None
        for k, v in RECORD_TYPES.items():
            if v == r["type"]:
                rt = k
                break  # Added break to prevent unnecessary iterations
        response += struct.pack(">HHI", rt, 1, r.get("ttl", 300))

        if r["type"] == "A":
            ip_bytes = socket.inet_aton(r["value"])
            response += struct.pack(">H", 4)
            response += ip_bytes
        elif r["type"] == "AAAA":
            ip_bytes = socket.inet_pton(socket.AF_INET6, r["value"])
            response += struct.pack(">H", 16)
            response += ip_bytes
        elif r["type"] == "NS":
            ns_encoded = encode_domain_name(r["value"])
            response += struct.pack(">H", len(ns_encoded))
            response += ns_encoded
        elif r["type"] == "MX":
            mx_encoded = encode_domain_name(r["value"])
            preference = r.get("preference", 10)
            length = 2 + len(mx_encoded)
            response += struct.pack(">H", length)
            response += struct.pack(">H", preference)
            response += mx_encoded
        elif r["type"] == "PTR":
            ptr_encoded = encode_domain_name(r["value"])
            response += struct.pack(">H", len(ptr_encoded))
            response += ptr_encoded
        elif r["type"] == "CNAME":  # Added CNAME handling
            cname_encoded = encode_domain_name(r["value"])
            response += struct.pack(">H", len(cname_encoded))
            response += cname_encoded
        else:
            # Unsupported type
            log(f"Unsupported record type: {r['type']}")

    return response

def build_nxdomain(transaction_id, domain, qtype):
    # NXDOMAIN
    response = struct.pack(">H", transaction_id)
    # 0x81 0x83 = standard query response, Name Error
    response += b"\x81\x83"
    # QD=1, AN=0, NS=0, AR=0
    response += struct.pack(">HHHH", 1, 0, 0, 0)
    response += encode_domain_name(domain)
    response += struct.pack(">HH", qtype, 1)
    return response


def parse_nxdomain_response(data):
    """
    Parse response from a known NXDOMAIN response built with build_nxdomain()
    """
    transaction_id = struct.unpack(">H", data[:2])[0]
    flags = struct.unpack(">H", data[2:4])[0]
    qdcount = struct.unpack(">H", data[4:6])[0]

    # Extract domain name from question section
    pos = 12
    domain_parts = []
    while data[pos] != 0:
        length = data[pos]
        pos += 1
        domain_parts.append(data[pos:pos + length].decode())
        pos += length
    domain = ".".join(domain_parts)

    # Extract query type
    qtype = struct.unpack(">H", data[pos + 1:pos + 3])[0]
    qtype_str = RECORD_TYPES.get(qtype, "UNKNOWN")

    #log(f"NXDOMAIN Response - Transaction ID: {transaction_id}, Domain: {domain}, Type: {qtype_str}")

    return transaction_id, domain, qtype_str

def build_query(domain, qtype, transaction_id=None):
    if transaction_id is None:
        # Generate a random transaction_id
        transaction_id = random.randint(0, 65535)
        log("here is"+str(transaction_id))
    transaction_id_bytes = struct.pack(">H", transaction_id)
    flags = b"\x01\x00"
    qdcount = b"\x00\x01"
    ancount = b"\x00\x00"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    qname = encode_domain_name(domain)
    qtype_b = struct.pack(">H", qtype)
    qclass_b = struct.pack(">H", 1)
    query = transaction_id_bytes + flags + qdcount + ancount + nscount + arcount + qname + qtype_b + qclass_b
    return query

def parse_response(data):
    transaction_id = struct.unpack(">H", data[:2])[0]
    flags = data[2:4]
    qdcount, ancount, nscount, arcount = struct.unpack(">HHHH", data[4:12])

    pos = 12
    # Skip Question
    for _ in range(qdcount):
        while data[pos] != 0:
            pos += data[pos] + 1
        pos += 1 + 4  # null + qtype/qclass

    records = []
    # Parse Answer
    for _ in range(ancount):
        # skip name
        pos += 2
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        rdata = data[pos:pos + rdlength]
        pos += rdlength

        rtype_str = RECORD_TYPES.get(rtype, None)
        if rtype_str == "A":
            ip = socket.inet_ntoa(rdata)
            records.append({"type": "A", "ttl": ttl, "value": ip})
        elif rtype_str == "AAAA":
            ip = socket.inet_ntop(socket.AF_INET6, rdata)
            records.append({"type": "AAAA", "ttl": ttl, "value": ip})
        elif rtype_str == "NS":
            ns = decode_domain_name(rdata)
            records.append({"type": "NS", "ttl": ttl, "value": ns})
        elif rtype_str == "MX":
            pref = struct.unpack(">H", rdata[:2])[0]
            mx = decode_domain_name(rdata[2:])
            records.append({"type": "MX", "ttl": ttl, "value": mx, "preference": pref})
        elif rtype_str == "PTR":
            ptr = decode_domain_name(rdata)
            records.append({"type": "PTR", "ttl": ttl, "value": ptr})
        elif rtype_str == "CNAME":
            cname= decode_domain_name(rdata)
            records.append({"type": "CNAME", "ttl": ttl, "value": cname})
        else:
            # Unsupported type
            log(f"Received unsupported record type: {rtype}")

    return transaction_id, records

def decode_domain_name(data):
    labels = []
    pos = 0
    while data[pos] != 0:
        length = data[pos]
        pos += 1
        labels.append(data[pos:pos + length].decode('ascii'))
        pos += length
    return ".".join(labels) + "."

def forward_query(domain, qtype, server_addr, transaction_id):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    query = build_query(domain, qtype, transaction_id)
    sock.sendto(query, server_addr)
    try:
        data, _ = sock.recvfrom(512)
        resp_transaction_id, records = parse_response(data)
        if resp_transaction_id != transaction_id:
            log(f"Transaction ID mismatch: expected {transaction_id}, got {resp_transaction_id}")
            return None
        return records
    except socket.timeout:
        log(f"Timeout querying {server_addr}")
        return None
    finally:
        sock.close()