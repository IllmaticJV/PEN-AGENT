# PEN-AGENT shell_recon — Windows one-shot deterministic recon. Pipe output
# to tools/ingestors/shell_recon.py --ip <this-host>.
Write-Host '=== WHOAMI ==='; whoami 2>$null
Write-Host '=== ID ==='; whoami /all 2>$null | Out-String
Write-Host '=== HOSTNAME ==='; hostname 2>$null
Write-Host '=== OS ==='; (Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue).Caption
Write-Host '=== KERNEL ==='; (Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue).Version
Write-Host '=== IFACES ==='; ipconfig | Select-String 'IPv4 Address' 2>$null
Write-Host '=== SUDO ==='; (whoami /groups) 2>$null | Select-String 'Administrators|BUILTIN|Domain Admins'
Write-Host '=== DOMAIN ==='; (Get-WmiObject Win32_ComputerSystem).Domain 2>$null
Write-Host '=== CWD ==='; (Get-Location).Path
Write-Host '=== LISTENING ==='; Get-NetTCPConnection -State Listen -EA SilentlyContinue | Select -First 20 LocalAddress,LocalPort,OwningProcess
Write-Host '=== DONE ==='
