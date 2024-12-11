import socket
import struct

class RootServer:
    def __init__(self, ip="127.0.0.1", port=53):
        self.ip = ip
        self.port = port
        self.tld_servers = {
            ".com": ("127.0.0.1", 1053),
            ".org": ("127.0.0.1", 2053),
        }

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
            server_socket.bind((self.ip, self.port))
            print(f"Root DNS Server running on {self.ip}:{self.port}...")

            while True:
                data, addr = server_socket.recvfrom(512)
                print(f"Received query from {addr}")

                # Decode DNS header
                header = self.decode_header(data)
                qname, qtype = self.decode_question(data[12:])

                # Print extracted details
                print(f"QName: {qname}, QType: {qtype}")

                # Forward to appropriate TLD server
                tld = self.extract_tld(qname)
                if tld in self.tld_servers:
                    tld_ip, tld_port = self.tld_servers[tld]
                    print(f"Forwarding query to TLD server {tld} at {tld_ip}:{tld_port}")
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tld_socket:
                        tld_socket.sendto(data, (tld_ip, tld_port))
                        response, _ = tld_socket.recvfrom(512)

                    # Send back the response to the client
                    server_socket.sendto(response, addr)

    def decode_header(self, data):
        # Extract and decode DNS header (first 12 bytes)
        header = struct.unpack("!HHHHHH", data[:12])
        return header

    def decode_question(self, data):
        # Decode the DNS question section
        qname, qtype, qclass = self.decode_qname_and_type(data)
        return qname, qtype

    def decode_qname_and_type(self, data):
        # Decode QName first
        qname, qname_length = self.decode_qname(data)

        # After decoding the QName, extract QType (2 bytes) and QClass (2 bytes)
        qtype, qclass = struct.unpack("!HH", data[qname_length:])
        return qname, qtype, qclass

    def decode_qname(self, data):
        qname = []
        i = 0
        length = data[i]
        while length != 0:
            i += 1
            qname.append(data[i:i + length].decode())
            i += length
            length = data[i]

        # Return the decoded QName as a string
        return ".".join(qname), i + 1  # i + 1 is the position after the null byte

    def extract_tld(self, qname):
        # Extract TLD from the domain name (assumes TLD is the last part)
        return "." + qname.split('.')[-1]

if __name__ == "__main__":
    root_server = RootServer()
    root_server.start()
