import socket
import struct

class AuthorizationServer:
    def __init__(self, domain_name, ip="127.0.0.1", port=3000):
        self.domain_name = domain_name
        self.ip = ip
        self.port = port
        self.records = {
            "example.com": "93.184.216.34",  # IP for example.com
        }

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
            server_socket.bind((self.ip, self.port))
            print(f"Authorization DNS Server for {self.domain_name} running on {self.ip}:{self.port}...")

            while True:
                data, addr = server_socket.recvfrom(512)
                print(f"Received query from {addr}")

                # Decode DNS header and question part
                qname, qtype, qclass = self.decode_question(data[12:])

                # Print extracted details
                print(f"QName: {qname}, QType: {qtype}, QClass: {qclass}")

                # Simulate a DNS response based on the domain name
                ip_address = self.records.get(qname, None)
                if ip_address:
                    response = self.create_response(qname, ip_address)
                else:
                    response = self.create_error_response()

                # Send back the response to the client
                server_socket.sendto(response, addr)

    def decode_question(self, data):
        # Decode the DNS question section
        qname, qname_length = self.decode_qname(data)

        # Extract the QType and QClass after the QName
        qtype, qclass = struct.unpack("!HH", data[qname_length: qname_length + 4])

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

        # Return the decoded QName as a string and the length of the QName part
        return ".".join(qname), i + 1  # i + 1 is the position after the null byte

    def create_response(self, qname, ip):
        # Construct a simplified DNS response with an A record
        response = (
            b'\x81\x80'  # Flags (Standard query response, No error)
            + b'\x00\x01'  # Question count
            + b'\x00\x01'  # Answer count
            + b'\x00\x00'  # Authority count
            + b'\x00\x00'  # Additional count
            + self.encode_qname(qname)  # Question section (QName)
            + b'\x00\x01'  # QType (A)
            + b'\x00\x01'  # QClass (IN)
            + b'\xc0\x0c'  # Pointer to QName in the answer section
            + b'\x00\x01'  # QType (A)
            + b'\x00\x01'  # QClass (IN)
            + b'\x00\x00\x00\x3c'  # TTL (60 seconds)
            + b'\x00\x04'  # Data length (4 bytes for IP)
            + socket.inet_aton(ip)  # IP address (A record)
        )
        return response

    def create_error_response(self):
        # Send back an error if no record is found
        return (
            b'\x81\x83'  # Flags (Standard query response, Name error)
            + b'\x00\x01'  # Question count
            + b'\x00\x00'  # Answer count
            + b'\x00\x00'  # Authority count
            + b'\x00\x00'  # Additional count
        )

    def encode_qname(self, qname):
        # Encode QName in DNS message format (length-prefixed labels)
        labels = qname.split(".")
        encoded = b""
        for label in labels:
            encoded += bytes([len(label)]) + label.encode()
        return encoded + b'\x00'  # Null byte to end the QName

if __name__ == "__main__":
    auth_server = AuthorizationServer(domain_name="example.com", port=3000)
    auth_server.start()
