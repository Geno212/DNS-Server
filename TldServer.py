import socket
import struct

class TldServer:
    def __init__(self, tld_name, ip="127.0.0.1", port=1053):
        self.tld_name = tld_name
        self.ip = ip
        self.port = port
        self.authorization_servers = {
            "example.com": ("127.0.0.1", 3000),
        }

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
            server_socket.bind((self.ip, self.port))
            print(f"TLD DNS Server for {self.tld_name} running on {self.ip}:{self.port}...")

            while True:
                data, addr = server_socket.recvfrom(512)
                print(f"Received query from {addr}")

                # Decode DNS header and question part
                qname, qtype, qclass = self.decode_question(data[12:])

                # Print extracted details
                print(f"QName: {qname}, QType: {qtype}, QClass: {qclass}")

                # Check if we have an authorization server for the domain
                if qname in self.authorization_servers:
                    auth_ip, auth_port = self.authorization_servers[qname]
                    print(f"Forwarding query to Authorization server for {qname} at {auth_ip}:{auth_port}")

                    # Forward the query to the appropriate Authorization server
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as auth_socket:
                        auth_socket.sendto(data, (auth_ip, auth_port))
                        response, _ = auth_socket.recvfrom(512)

                    # Send back the response to the client
                    server_socket.sendto(response, addr)

    def decode_question(self, data):
        # Decode the DNS question section
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

if __name__ == "__main__":
    tld_server = TldServer(tld_name=".com", port=1053)
    tld_server.start()
