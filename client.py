import socket
import struct


class DNSClient:
    def __init__(self, server_ip="8.8.8.8", server_port=53):
        self.server_ip = server_ip
        self.server_port = server_port

    def send_query(self, domain_name):
        query_data = self.create_query(domain_name)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
            client_socket.settimeout(5)  # Set a timeout
            client_socket.sendto(query_data, (self.server_ip, self.server_port))
            try:
                response, _ = client_socket.recvfrom(512)
                print(f"Received raw response: {response}")
                print(f"Response (hex): {response.hex()}")
                self.decode_response(response)
            except socket.timeout:
                print("Query timed out")

    def create_query(self, domain_name):
        header = b'\x12\x34'  # Transaction ID
        flags = b'\x01\x00'  # Standard query
        qcount = b'\x00\x01'  # One question
        acount = b'\x00\x00'  # No answers yet
        ncount = b'\x00\x00'  # No authority records
        arcount = b'\x00\x00'  # No additional records

        qname = self.encode_qname(domain_name)
        qtype = b'\x00\x01'  # Query type (A record)
        qclass = b'\x00\x01'  # Class (IN - Internet)

        query = header + flags + qcount + acount + ncount + arcount + qname + qtype + qclass
        return query

    def encode_qname(self, qname):
        labels = qname.split(".")
        encoded = b""
        for label in labels:
            encoded += bytes([len(label)]) + label.encode()
        return encoded + b'\x00'  # Null byte to end the domain name

    def decode_response(self, response):
        try:
            # Decode the header
            transaction_id, flags, qcount, acount, ncount, arcount = struct.unpack("!HHHHHH", response[:12])
            print(f"Transaction ID: {transaction_id}")
            print(f"Flags: {flags:04x}")
            print(f"Questions: {qcount}, Answers: {acount}, Authorities: {ncount}, Additional: {arcount}")

            # Parse the question section (skip the header)
            offset = 12
            qname, offset = self.decode_qname(response, offset)
            qtype, qclass = struct.unpack("!HH", response[offset:offset + 4])
            print(f"Query: {qname}, Type: {qtype}, Class: {qclass}")
            offset += 4

            # Parse the answer section
            for _ in range(acount):
                # Handle name (could be direct or compressed)
                name, offset = self.decode_qname(response, offset)

                # Extract answer details
                answer_type, answer_class, ttl, data_len = struct.unpack("!HHIH", response[offset:offset + 10])
                offset += 10

                # Process A record (IPv4)
                if answer_type == 1:  # A record
                    if data_len == 4:  # IPv4 address
                        ip_bytes = response[offset:offset + 4]
                        ip_address = '.'.join(str(b) for b in ip_bytes)
                        print(f"IP Address: {ip_address}")

                # Move offset to next record
                offset += data_len

        except struct.error as e:
            print(f"Error decoding response: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    def decode_qname(self, response, offset):
        labels = []
        original_offset = offset

        while True:
            if offset >= len(response):
                raise ValueError("Offset out of range while decoding domain name")

            length = response[offset]
            offset += 1

            if length == 0:
                # End of domain name
                break
            elif length & 0xC0 == 0xC0:
                # Compression pointer
                pointer = ((length & 0x3F) << 8) + response[offset]
                offset += 1
                # Recursively resolve the pointer
                temp_name, _ = self.decode_qname(response, pointer)
                labels.append(temp_name)
                break
            else:
                # Normal label
                if offset + length > len(response):
                    raise ValueError("Label length exceeds response length")
                label = response[offset:offset + length].decode(errors='ignore')
                labels.append(label)
                offset += length

        return '.'.join(labels), offset


if __name__ == "__main__":
    client = DNSClient()  # Using Google's public DNS server
    client.send_query("example.com")