# Unit tests for the pure helpers in target/windows/tna-target.ps1.
# Runs on Windows PowerShell 5.1 and PowerShell 7 (also on Linux/macOS).
# Usage: pwsh -NoProfile -File tests/target_windows_unit.ps1 [-InfoOut file]
param([string]$InfoOut)
$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot '..\target\windows\tna-target.ps1'
$script = [IO.Path]::GetFullPath(($script -replace '\\', [IO.Path]::DirectorySeparatorChar))
. $script __lib

$failed = 0
function Check([string]$Name, [bool]$Cond) {
    if ($Cond) { Write-Host "ok   $Name" } else { Write-Host "FAIL $Name"; $script:failed++ }
}

$key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOd7kmdX0s1yX6WbqcvJ6oFqRk0zjYH7d7nU2c8gk1nL tna-operator:alice@pc'
Check 'valid pubkey' (Test-PubKey $key)
Check 'reject non-key blob' (-not (Test-PubKey 'ssh-ed25519 Zm9vYmFy comment'))
Check 'reject type mismatch' (-not (Test-PubKey ('ssh-rsa ' + ($key -split ' ')[1])))
Check 'reject option injection' (-not (Test-PubKey 'command="x" ssh-ed25519 AAAA'))
Check 'label sanitized' ((Get-SafeLabel 'a b/c"d') -eq 'a-b-c-d')
Check 'label default' ((Get-SafeLabel '') -eq 'operator')

$now = [datetime]::new(2026, 11, 3, 13, 42, 0, [DateTimeKind]::Utc)
Check 'expiry 7d' ((Get-ExpiryStamp '7d' $now) -eq '202611101342Z')
Check 'expiry 8h' ((Get-ExpiryStamp '8h' $now) -eq '202611032142Z')
Check 'expiry never' ((Get-ExpiryStamp 'never' $now) -eq '')
$threw = $false; try { Get-ExpiryStamp '7w' $now | Out-Null } catch { $threw = $true }
Check 'expiry bad spec throws' $threw

$line = New-KeyLine -Key $key -KeyLabel 'alice' -KeyId 'deadbeef' -From '100.64.0.0/10,fd7a:115c:a1e0::/48' -Expiry '202611101342Z'
$expected = 'restrict,pty,from="100.64.0.0/10,fd7a:115c:a1e0::/48",expiry-time="202611101342Z" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOd7kmdX0s1yX6WbqcvJ6oFqRk0zjYH7d7nU2c8gk1nL tna:alice:deadbeef'
Check 'key line format' ($line -eq $expected)
$line2 = New-KeyLine -Key $key -KeyLabel 'bob' -KeyId '0123abcd' -From '' -Expiry ''
Check 'key line minimal' ($line2 -eq 'restrict,pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOd7kmdX0s1yX6WbqcvJ6oFqRk0zjYH7d7nU2c8gk1nL tna:bob:0123abcd')

$tmp = [IO.Path]::GetTempFileName()
Write-KeyFile -Path $tmp -Lines @('ssh-ed25519 AAAAOTHER other@host')
Add-KeyLine -Path $tmp -Line $line
Add-KeyLine -Path $tmp -Line $line2
Check 'three lines' (@(Get-Content $tmp).Count -eq 3)
$bytes = [IO.File]::ReadAllBytes($tmp)
Check 'no BOM' (-not ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB))
Check 'remove by label' ((Remove-TnaLines -Path $tmp -KeyLabel 'bob') -eq 1)
Check 'other key kept' ((Get-Content $tmp) -contains 'ssh-ed25519 AAAAOTHER other@host')
Check 'remove all tna' ((Remove-TnaLines -Path $tmp -KeyLabel '') -eq 1)
Check 'only foreign key left' (@(Get-Content $tmp).Count -eq 1)
Check 'missing file -> 0' ((Remove-TnaLines -Path ($tmp + '.nope') -KeyLabel '') -eq 0)
Remove-Item $tmp

Check 'fingerprint' ((Get-KeyFingerprint $key) -match '^SHA256:[A-Za-z0-9+/]{43}$')
Check 'shell cmd' ((Get-ShellKind '') -eq 'cmd')
Check 'shell powershell' ((Get-ShellKind 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe') -eq 'powershell')
Check 'shell pwsh' ((Get-ShellKind 'C:\Program Files\PowerShell\7\pwsh.exe') -eq 'powershell')
Check 'expiry supported 9.5' (Test-ExpirySupported '9.5.4.1')
Check 'expiry unsupported 8.1' (-not (Test-ExpirySupported '8.1.0.1'))
Check 'expiry unsupported empty' (-not (Test-ExpirySupported ''))

$info = @{ v = 1; name = 'desk-pc'; os = 'windows'; user = 'Alice Wang'; host = '100.101.102.103'; ip = '100.101.102.103'
    hostkey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOd7kmdX0s1yX6WbqcvJ6oFqRk0zjYH7d7nU2c8gk1nL'; shell = 'cmd'
    cua = 'C:\Users\Alice Wang\AppData\Local\Programs\Cua\cua-driver\bin\cua-driver.exe'; socket = '\\.\pipe\cua-driver'
    expires = '202611101342Z'; keyid = 'deadbeef'; created = '2026-11-03T13:42:00Z' }
$il = ConvertTo-InfoLine $info
Check 'info line prefix' ($il.StartsWith('TNA1:'))
Check 'info line url-safe' ($il.Substring(5) -match '^[A-Za-z0-9_-]+$')
if ($InfoOut) { Set-Content -LiteralPath $InfoOut -Value $il -Encoding ASCII }

if ($failed) { Write-Host "$failed test(s) failed"; exit 1 }
Write-Host 'all windows unit tests passed'
