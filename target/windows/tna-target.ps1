<#
.SYNOPSIS
  tailnet-assist target side for Windows 10/11.

.DESCRIPTION
  Run by the OWNER of the machine, in PowerShell inside their logged-in
  desktop session (not over SSH, not as SYSTEM). Shows what will change and
  needs the owner to type YES. Steps that need administrator rights are run
  in a separate elevated window (UAC prompt).

    powershell -ExecutionPolicy Bypass -File tna-target.ps1 setup -OperatorKey 'ssh-ed25519 AAAA...' [-Expires 7d]
    powershell -ExecutionPolicy Bypass -File tna-target.ps1 status
    powershell -ExecutionPolicy Bypass -File tna-target.ps1 revoke [-Label NAME]
    powershell -ExecutionPolicy Bypass -File tna-target.ps1 uninstall [-LogoutTailscale] [-RemoveOpenSSH]

  No new port is opened to the internet or LAN: the OpenSSH firewall rule is
  limited to Tailscale addresses when this script installs OpenSSH, the
  operator key only works from Tailscale addresses (from=...), and Cua
  Driver only listens on the local named pipe \\.\pipe\cua-driver.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('setup', 'status', 'revoke', 'uninstall', 'admin-setup', 'admin-revoke', 'admin-uninstall', '__lib')]
    [string]$Action = 'setup',
    [string]$OperatorKey,
    [string]$Expires = '7d',
    [string]$Label = 'operator',
    [string]$Name,
    [switch]$Yes,
    [switch]$SkipTailscale,
    [switch]$SkipSshServer,
    [switch]$SkipCua,
    [switch]$KeepTelemetry,
    [string]$AllowFrom = '100.64.0.0/10,fd7a:115c:a1e0::/48',
    [string]$HostOverride,
    [switch]$LogoutTailscale,
    [switch]$RemoveOpenSSH,
    [string]$RequestFile
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$TnaVersion = '0.1.0'
$CuaInstallUrl = 'https://cua.ai/driver/install.ps1'
$TsPkgIndex = 'https://pkgs.tailscale.com/stable/?mode=json'
$TsPkgBase = 'https://pkgs.tailscale.com/stable/'
$MarkerPattern = ' tna:[A-Za-z0-9._-]+:[0-9a-f]+$'

function Get-TnaPaths {
    $pd = if ($env:TNA_PROGRAMDATA) { $env:TNA_PROGRAMDATA } else { $env:ProgramData }
    $la = if ($env:TNA_LOCALAPPDATA) { $env:TNA_LOCALAPPDATA } else { $env:LOCALAPPDATA }
    $up = if ($env:TNA_USERPROFILE) { $env:TNA_USERPROFILE } else { $env:USERPROFILE }
    [pscustomobject]@{
        MachineState    = Join-Path $pd 'tailnet-assist\state.json'
        UserStateDir    = Join-Path $la 'tailnet-assist'
        SshDir          = Join-Path $pd 'ssh'
        AdminKeys       = Join-Path $pd 'ssh\administrators_authorized_keys'
        UserKeys        = Join-Path $up '.ssh\authorized_keys'
        CuaExe          = Join-Path $la 'Programs\Cua\cua-driver\bin\cua-driver.exe'
    }
}

# ------------------------------------------------------------------ pure helpers (unit tested)

function Test-PubKey([string]$Key) {
    if ($Key -notmatch '^(ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-rsa) ([A-Za-z0-9+/]+={0,3})( .*)?$') { return $false }
    $type = $Matches[1]
    try { $blob = [Convert]::FromBase64String($Matches[2]) } catch { return $false }
    # The blob starts with a 4-byte length and the key type again.
    if ($blob.Length -lt (4 + $type.Length)) { return $false }
    $len = ([int]$blob[0] -shl 24) -bor ([int]$blob[1] -shl 16) -bor ([int]$blob[2] -shl 8) -bor [int]$blob[3]
    if ($len -ne $type.Length) { return $false }
    return ([Text.Encoding]::ASCII.GetString($blob, 4, $len) -eq $type)
}

function Get-SafeLabel([string]$Value) {
    $s = ($Value -replace '[^A-Za-z0-9._-]', '-')
    if ($s.Length -gt 40) { $s = $s.Substring(0, 40) }
    if (-not $s) { $s = 'operator' }
    return $s
}

function Get-ExpiryStamp([string]$Spec, [datetime]$NowUtc = [datetime]::UtcNow) {
    if ($Spec -eq 'never') { return '' }
    if ($Spec -notmatch '^(\d{1,3})([hd])$') { throw "Expires must look like 8h, 7d or never (got '$Spec')" }
    $n = [int]$Matches[1]
    $t = if ($Matches[2] -eq 'h') { $NowUtc.AddHours($n) } else { $NowUtc.AddDays($n) }
    return $t.ToString('yyyyMMddHHmm', [Globalization.CultureInfo]::InvariantCulture) + 'Z'
}

function New-KeyLine([string]$Key, [string]$KeyLabel, [string]$KeyId, [string]$From, [string]$Expiry) {
    $parts = $Key.Trim() -split '\s+'
    $opts = 'restrict,pty'
    if ($From) { $opts += ",from=`"$From`"" }
    if ($Expiry) { $opts += ",expiry-time=`"$Expiry`"" }
    return "$opts $($parts[0]) $($parts[1]) tna:${KeyLabel}:$KeyId"
}

function Remove-TnaLines([string]$Path, [string]$KeyLabel) {
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $pattern = if ($KeyLabel) { " tna:$([regex]::Escape($KeyLabel)):[0-9a-f]+$" } else { $MarkerPattern }
    $lines = @(Get-Content -LiteralPath $Path -Encoding UTF8)
    $keep = @($lines | Where-Object { $_ -notmatch $pattern })
    $removed = $lines.Count - $keep.Count
    if ($removed -gt 0) { Write-KeyFile -Path $Path -Lines $keep }
    return $removed
}

function Write-KeyFile([string]$Path, [string[]]$Lines) {
    # sshd on Windows wants UTF-8 without BOM
    $text = if ($Lines -and $Lines.Count) { ($Lines -join "`n") + "`n" } else { '' }
    [IO.File]::WriteAllText($Path, $text, (New-Object Text.UTF8Encoding($false)))
}

function Add-KeyLine([string]$Path, [string]$Line) {
    $lines = @()
    if (Test-Path -LiteralPath $Path) { $lines = @(Get-Content -LiteralPath $Path -Encoding UTF8 | Where-Object { $_ -ne '' }) }
    Write-KeyFile -Path $Path -Lines (@($lines) + $Line)
}

function Get-KeyFingerprint([string]$Key) {
    $blob = [Convert]::FromBase64String(($Key.Trim() -split '\s+')[1])
    $sha = [Security.Cryptography.SHA256]::Create()
    return 'SHA256:' + ([Convert]::ToBase64String($sha.ComputeHash($blob))).TrimEnd('=')
}

function ConvertTo-InfoLine([hashtable]$Info) {
    $json = $Info | ConvertTo-Json -Compress
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    return 'TNA1:' + $b64.TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-ShellKind([string]$DefaultShell) {
    if ($DefaultShell -match '(powershell|pwsh)(\.exe)?$') { return 'powershell' }
    return 'cmd'
}

function Test-ExpirySupported([string]$SshdVersion) {
    # expiry-time in authorized_keys needs OpenSSH 8.2+
    try { $v = [version](($SshdVersion -split '[^0-9.]')[0]) } catch { return $false }
    return ($v -ge [version]'8.2')
}

# ------------------------------------------------------------------ environment helpers

function Say([string]$m) { Write-Host $m }
function Step([string]$m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Warn([string]$m) { Write-Host "注意: $m" -ForegroundColor Yellow }

function Confirm-Step([string]$Question) {
    if ($Yes) { return $true }
    $a = Read-Host "$Question [y/N]"
    return ($a -eq 'y' -or $a -eq 'Y' -or $a -eq 'yes')
}

function Test-Elevated {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-UserIsAdminMember {
    # Includes UAC-filtered (deny-only) membership. Uses SIDs, so it works on localized Windows.
    $rows = whoami /groups /fo csv /nh 2>$null
    foreach ($r in $rows) { if ($r -match '"S-1-5-32-544"') { return $true } }
    return $false
}

function Get-LoginName {
    if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME) { return "$env:USERDOMAIN\$env:USERNAME" }
    return $env:USERNAME
}

function Get-SshdPath { Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe' }

function Get-SshdVersion {
    $p = Get-SshdPath
    if (Test-Path -LiteralPath $p) { return (Get-Item -LiteralPath $p).VersionInfo.ProductVersion }
    return ''
}

function Test-AdminKeysFileInUse([string]$SshdConfig) {
    if (-not (Test-Path -LiteralPath $SshdConfig)) { return $true }  # default config uses it
    foreach ($l in Get-Content -LiteralPath $SshdConfig) {
        if ($l -match '^\s*Match\s+Group\s+administrators\s*$') { return $true }
    }
    return $false
}

function Get-TailscaleExe {
    $c = Get-Command tailscale.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    $p = Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'
    if (Test-Path -LiteralPath $p) { return $p }
    return $null
}

function Get-TailscaleIp {
    $ts = Get-TailscaleExe
    if (-not $ts) { return $null }
    $ip = & $ts ip -4 2>$null | Select-Object -First 1
    if ($LASTEXITCODE -eq 0 -and $ip) { return $ip.Trim() }
    return $null
}

function Read-MachineState {
    $p = (Get-TnaPaths).MachineState
    if (Test-Path -LiteralPath $p) {
        $o = Get-Content -LiteralPath $p -Raw | ConvertFrom-Json
        $h = @{}; foreach ($pr in $o.PSObject.Properties) { $h[$pr.Name] = $pr.Value }; return $h
    }
    return @{}
}

function Save-MachineState([hashtable]$State) {
    $p = (Get-TnaPaths).MachineState
    $d = Split-Path $p
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
    ($State | ConvertTo-Json) | Set-Content -LiteralPath $p -Encoding UTF8
}

function Protect-AdminKeysFile([string]$Path) {
    # Same ACL Microsoft documents (Administrators + SYSTEM only), by SID so it works on localized Windows.
    & icacls.exe $Path /inheritance:r /grant '*S-1-5-32-544:F' /grant '*S-1-5-18:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $Path" }
}

# ------------------------------------------------------------------ elevated part

function Get-ReqValue($Req, [string]$Key) {
    if ($Req -and ($Req.PSObject.Properties.Name -contains $Key)) { return $Req.$Key }
    return $null
}

function Invoke-Elevated([string]$AdminAction, [hashtable]$Request) {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("tna-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    $req = Join-Path $tmp 'request.json'
    $Request['result'] = Join-Path $tmp 'result.json'
    ($Request | ConvertTo-Json) | Set-Content -LiteralPath $req -Encoding UTF8
    if (Test-Elevated) {
        & $PSCommandPath $AdminAction -RequestFile $req
    } else {
        Say '需要管理员权限的步骤会在一个新窗口里进行，请在 UAC 弹窗里确认。'
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", $AdminAction, '-RequestFile', "`"$req`"")
        $p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList -Wait -PassThru
        if ($p.ExitCode -ne 0) { throw "管理员步骤失败（退出码 $($p.ExitCode)），详见那个窗口的输出" }
    }
    if (-not (Test-Path -LiteralPath $Request['result'])) { throw '管理员步骤没有返回结果' }
    $o = Get-Content -LiteralPath $Request['result'] -Raw | ConvertFrom-Json
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    return $o
}

function Install-TailscaleMsi {
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } elseif ([Environment]::Is64BitOperatingSystem) { 'amd64' } else { 'x86' }
    $idx = Invoke-RestMethod -UseBasicParsing $TsPkgIndex
    $msi = $idx.MSIs.$arch
    if (-not $msi) { throw "找不到 $arch 的 Tailscale 安装包" }
    $f = Join-Path ([IO.Path]::GetTempPath()) $msi
    Say "下载 $TsPkgBase$msi"
    Invoke-WebRequest -UseBasicParsing ($TsPkgBase + $msi) -OutFile $f
    $sig = Get-AuthenticodeSignature -FilePath $f
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Tailscale') {
        throw "Tailscale 安装包签名校验失败: $($sig.Status) $($sig.SignerCertificate.Subject)"
    }
    $p = Start-Process msiexec.exe -ArgumentList @('/i', "`"$f`"", '/passive', '/norestart') -Wait -PassThru
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { throw "Tailscale 安装失败（msiexec $($p.ExitCode)）" }
}

function Invoke-AdminSetup($Req) {
    $paths = Get-TnaPaths
    $state = Read-MachineState
    $result = @{ ok = $true }
    if ((Get-ReqValue $Req 'installTailscale') -and -not (Get-TailscaleExe)) {
        Step '安装 Tailscale'
        Install-TailscaleMsi
        $state['installedTailscale'] = $true
    }
    if (Get-ReqValue $Req 'ensureSshd') {
        Step 'OpenSSH 服务端（Windows 自带组件）'
        if (-not (Test-Path -LiteralPath (Get-SshdPath))) {
            $cap = Get-WindowsCapability -Online | Where-Object { $_.Name -like 'OpenSSH.Server*' } | Select-Object -First 1
            if (-not $cap) { throw '这台 Windows 没有 OpenSSH.Server 可选组件' }
            Say "安装 $($cap.Name)（可能要几分钟）"
            Add-WindowsCapability -Online -Name $cap.Name | Out-Null
            $state['installedSshd'] = $true
        }
        $svc = Get-Service sshd -ErrorAction Stop
        if ($svc.StartType -ne 'Automatic') { Set-Service sshd -StartupType Automatic; $state['setSshdAutomatic'] = $true }
        if ($svc.Status -ne 'Running') { Start-Service sshd }
        $rule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
        $remote = @((Get-ReqValue $Req 'allowFrom') -split ',' | Where-Object { $_ })
        if ($state['installedSshd']) {
            if ($rule) {
                if (-not $state.ContainsKey('firewallOriginal')) {
                    $state['firewallOriginal'] = @(($rule | Get-NetFirewallAddressFilter).RemoteAddress)
                }
                Set-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -RemoteAddress $remote
            } else {
                New-NetFirewallRule -Name 'tna-sshd-tailnet' -DisplayName 'OpenSSH Server (tailnet-assist, Tailscale only)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -RemoteAddress $remote | Out-Null
                $state['firewallCreated'] = $true
            }
            Say "防火墙: 22 端口只允许来自 $(Get-ReqValue $Req 'allowFrom') 的连接"
        } else {
            Warn 'OpenSSH 服务端原来就装着，防火墙规则保持原样没动。控制端密钥本身只接受来自 Tailscale 地址的连接。'
        }
        $hk = Join-Path $paths.SshDir 'ssh_host_ed25519_key.pub'
        for ($i = 0; $i -lt 20 -and -not (Test-Path -LiteralPath $hk); $i++) { Start-Sleep -Milliseconds 500 }
        if (-not (Test-Path -LiteralPath $hk)) { throw "找不到主机公钥 $hk" }
        $result['hostkey'] = ((Get-Content -LiteralPath $hk -Raw).Trim() -split '\s+')[0..1] -join ' '
        $shell = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -ErrorAction SilentlyContinue)
        $result['shell'] = Get-ShellKind $(if ($shell) { $shell.DefaultShell } else { '' })
        $result['sshdVersion'] = Get-SshdVersion
        $result['adminKeysInUse'] = Test-AdminKeysFileInUse (Join-Path $paths.SshDir 'sshd_config')
    }
    $result['keyFile'] = 'none'
    if (Get-ReqValue $Req 'writeAdminKey') {
        $inUse = Test-AdminKeysFileInUse (Join-Path $paths.SshDir 'sshd_config')
        $result['adminKeysInUse'] = $inUse
        if ($inUse) {
            Step '写入 administrators_authorized_keys（管理员账号的 SSH 公钥文件）'
            $expiry = [string](Get-ReqValue $Req 'expiry')
            if ($expiry -and -not (Test-ExpirySupported (Get-SshdVersion))) { $expiry = '' }
            $line = New-KeyLine -Key (Get-ReqValue $Req 'operatorKey') -KeyLabel (Get-ReqValue $Req 'label') -KeyId (Get-ReqValue $Req 'keyId') -From (Get-ReqValue $Req 'allowFrom') -Expiry $expiry
            $f = $paths.AdminKeys
            if (-not (Test-Path -LiteralPath $f)) { New-Item -ItemType File -Path $f -Force | Out-Null }
            $n = Remove-TnaLines -Path $f -KeyLabel (Get-ReqValue $Req 'label')
            if ($n -gt 0) { Say "替换了同标签的旧授权 $n 条" }
            Add-KeyLine -Path $f -Line $line
            Protect-AdminKeysFile $f
            $state['adminKeys'] = $true
            $result['keyFile'] = 'admin'
            $result['expiryApplied'] = $expiry
            Say "已写入 $f"
        }
    }
    Save-MachineState $state
    ($result | ConvertTo-Json) | Set-Content -LiteralPath (Get-ReqValue $Req 'result') -Encoding UTF8
}

function Invoke-AdminRevoke($Req) {
    $n = Remove-TnaLines -Path (Get-TnaPaths).AdminKeys -KeyLabel ([string](Get-ReqValue $Req 'label'))
    (@{ ok = $true; removed = $n } | ConvertTo-Json) | Set-Content -LiteralPath (Get-ReqValue $Req 'result') -Encoding UTF8
}

function Invoke-AdminUninstall($Req) {
    $paths = Get-TnaPaths
    $state = Read-MachineState
    $n = Remove-TnaLines -Path $paths.AdminKeys -KeyLabel ''
    if ($state['firewallCreated']) { Remove-NetFirewallRule -Name 'tna-sshd-tailnet' -ErrorAction SilentlyContinue }
    if ($state.ContainsKey('firewallOriginal')) {
        Set-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -RemoteAddress @($state['firewallOriginal']) -ErrorAction SilentlyContinue
    }
    if ($state['installedSshd'] -or $state['setSshdAutomatic']) {
        Stop-Service sshd -ErrorAction SilentlyContinue
        Set-Service sshd -StartupType Manual -ErrorAction SilentlyContinue
        Say '已停止 sshd 并改回手动启动'
    }
    if ((Get-ReqValue $Req 'removeOpenSSH') -and $state['installedSshd']) {
        $cap = Get-WindowsCapability -Online | Where-Object { $_.Name -like 'OpenSSH.Server*' -and $_.State -eq 'Installed' } | Select-Object -First 1
        if ($cap) { Remove-WindowsCapability -Online -Name $cap.Name | Out-Null; Say '已卸载 OpenSSH 服务端' }
    }
    Remove-Item -LiteralPath $paths.MachineState -ErrorAction SilentlyContinue
    (@{ ok = $true; removed = $n } | ConvertTo-Json) | Set-Content -LiteralPath (Get-ReqValue $Req 'result') -Encoding UTF8
}

# ------------------------------------------------------------------ user-level actions

function Initialize-Tailscale {
    Step 'Tailscale（两台机器之间的加密虚拟网络）'
    $ts = Get-TailscaleExe
    if (-not $ts) { throw '还是找不到 tailscale.exe' }
    if (-not (Get-TailscaleIp)) {
        Say '需要登录 Tailscale。登录哪个账号/网络由你决定：这决定了哪些设备能看到本机。'
        if ($env:TNA_TS_AUTHKEY) {
            $kf = [IO.Path]::GetTempFileName()
            [IO.File]::WriteAllText($kf, $env:TNA_TS_AUTHKEY)
            try { & $ts up "--auth-key=file:$kf" } finally { Remove-Item $kf -Force }
        } else {
            & $ts up
        }
    }
    $ip = Get-TailscaleIp
    if (-not $ip) { throw 'Tailscale 没有分到地址，请检查 Tailscale 托盘图标的状态' }
    Say "Tailscale 地址: $ip"
    return $ip
}

function Initialize-Cua {
    Step 'Cua Driver（截图、点击、键盘，只通过本机命名管道 \\.\pipe\cua-driver 提供服务）'
    $exe = (Get-TnaPaths).CuaExe
    if (-not (Test-Path -LiteralPath $exe)) {
        Say "将运行 Cua Driver 官方安装脚本: $CuaInstallUrl（MIT 许可，装到当前用户目录，不需要管理员）"
        if (-not (Confirm-Step '安装 Cua Driver？')) { throw '已取消' }
        $f = Join-Path ([IO.Path]::GetTempPath()) 'cua-driver-install.ps1'
        Invoke-WebRequest -UseBasicParsing $CuaInstallUrl -OutFile $f
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $f
        if ($LASTEXITCODE -ne 0) { throw "Cua Driver 安装失败（$LASTEXITCODE）" }
        $u = Join-Path (Get-TnaPaths).UserStateDir 'user.json'
        (@{ installedCua = $true } | ConvertTo-Json) | Set-Content -LiteralPath $u -Encoding UTF8
        if (-not (Test-Path -LiteralPath $exe)) { throw "安装后找不到 $exe" }
    }
    if (-not $KeepTelemetry) { & $exe telemetry disable *> $null; Say '已关闭 Cua Driver 使用统计' }
    & $exe autostart enable *> $null
    & $exe autostart kick *> $null
    $running = $false
    for ($i = 0; $i -lt 20; $i++) {
        $s = (& $exe status 2>&1 | Out-String)
        if ($s -match 'is running') { $running = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if ($running) { Say 'Cua Driver 守护进程已在当前桌面会话运行，登录时会自动启动' }
    else { Warn "Cua Driver 守护进程没有跑起来，请运行 `"$exe`" doctor 查看" }
    return $exe
}

function Invoke-Setup {
    $paths = Get-TnaPaths
    if (-not $OperatorKey) { throw '缺少 -OperatorKey（由控制端 tna invite 生成）' }
    if (-not (Test-PubKey $OperatorKey)) { throw '-OperatorKey 不是有效的 SSH 公钥' }
    $lbl = Get-SafeLabel $Label
    $null = Get-ExpiryStamp $Expires
    if ($env:SSH_CONNECTION -and -not $SkipCua) { throw '请在本机桌面里打开 PowerShell 运行，不要通过 SSH 运行（Cua Driver 必须跑在桌面会话里）' }
    $isAdminUser = Test-UserIsAdminMember
    $fp = Get-KeyFingerprint $OperatorKey
    $login = Get-LoginName
    $keyFile = if ($isAdminUser) { $paths.AdminKeys } else { $paths.UserKeys }
    Write-Host @"
================ tailnet-assist $TnaVersion 远程协助授权 ================
你将允许下面这把密钥的持有人，以当前用户 $login 的身份：
  - 通过 SSH 在本机运行命令（权限等同于你当前账号$(if ($isAdminUser) { '，你是管理员' } else { '' })）
  - 通过 Cua Driver 查看你的屏幕、点击、打字（你会看到它的操作）
密钥指纹: $fp   标签: $lbl
有效期: $Expires        只接受来自: $AllowFrom
将要做的事:
  $(if ($SkipTailscale) { '-' } else { '✓' }) 安装/登录 Tailscale
  $(if ($SkipSshServer) { '-' } else { '✓' }) 安装/启用 Windows 自带的 OpenSSH 服务端（防火墙只放行 Tailscale 地址）
  ✓ 把上面的公钥写入 $keyFile
  $(if ($SkipCua) { '-' } else { '✓' }) 安装 Cua Driver 并在你登录桌面时自动启动
随时撤销: 再次运行本脚本加 revoke     全部还原: 加 uninstall
=============================================================
"@
    if (-not $Yes) {
        $a = Read-Host '请核对指纹与对方告诉你的一致。同意请输入 YES'
        if ($a -cne 'YES') { throw '未同意，什么都没改' }
    }
    if (-not (Test-Path $paths.UserStateDir)) { New-Item -ItemType Directory -Path $paths.UserStateDir | Out-Null }

    $expiry = Get-ExpiryStamp $Expires
    $keyId = -join ((1..8) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
    $installTs = (-not $SkipTailscale) -and -not (Get-TailscaleExe)
    $adminResult = $null
    if ((-not $SkipSshServer) -or $installTs -or $isAdminUser) {
        # One UAC prompt for everything that needs administrator rights.
        $req = @{
            installTailscale = $installTs
            ensureSshd = (-not $SkipSshServer)
            writeAdminKey = $isAdminUser
            operatorKey = $OperatorKey
            label = $lbl
            keyId = $keyId
            allowFrom = $AllowFrom
            expiry = $expiry
        }
        $adminResult = Invoke-Elevated 'admin-setup' $req
    }
    $sshdVersion = Get-SshdVersion
    if ($expiry -and -not (Test-ExpirySupported $sshdVersion)) {
        Warn "本机 OpenSSH 版本 $sshdVersion 不支持 expiry-time，授权不会自动到期，用完请运行 revoke"
        $expiry = ''
    }
    if (-not ($adminResult -and $adminResult.keyFile -eq 'admin')) {
        Step '授权控制端的 SSH 公钥'
        $line = New-KeyLine -Key $OperatorKey -KeyLabel $lbl -KeyId $keyId -From $AllowFrom -Expiry $expiry
        $d = Split-Path $paths.UserKeys
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
        $n = Remove-TnaLines -Path $paths.UserKeys -KeyLabel $lbl
        if ($n -gt 0) { Say "替换了同标签的旧授权 $n 条" }
        Add-KeyLine -Path $paths.UserKeys -Line $line
        Say "已写入 $($paths.UserKeys)"
    }

    $hostAddr = $HostOverride
    if (-not $SkipTailscale) { $ip = Initialize-Tailscale; if (-not $hostAddr) { $hostAddr = $ip } }
    if (-not $hostAddr) { throw '不知道本机地址（跳过 Tailscale 时请用 -HostOverride 指定）' }
    $cua = $null
    if (-not $SkipCua) { $cua = Initialize-Cua }

    $hostkey = $null; $shell = 'cmd'
    if ($adminResult -and ($adminResult.PSObject.Properties.Name -contains 'hostkey')) { $hostkey = $adminResult.hostkey; $shell = $adminResult.shell }
    else {
        $hk = Join-Path $paths.SshDir 'ssh_host_ed25519_key.pub'
        if (Test-Path -LiteralPath $hk) { $hostkey = ((Get-Content -LiteralPath $hk -Raw).Trim() -split '\s+')[0..1] -join ' ' }
    }
    if (-not $hostkey) { throw '读不到 SSH 主机公钥' }
    $nm = if ($Name) { $Name } else { $env:COMPUTERNAME }
    $nm = ($nm.ToLowerInvariant() -replace '[^a-z0-9-]', '-')
    $info = [ordered]@{ v = 1; name = $nm; os = 'windows'; user = $login; host = $hostAddr; ip = $hostAddr; hostkey = $hostkey; shell = $shell }
    if ($cua) { $info['cua'] = $cua; $info['socket'] = '\\.\pipe\cua-driver' }
    if ($env:TNA_SSH_PORT) { $info['port'] = [int]$env:TNA_SSH_PORT }
    $info['expires'] = $(if ($expiry) { $expiry } else { 'never' })
    $info['keyid'] = $keyId
    $info['created'] = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $h = @{}; foreach ($k in $info.Keys) { $h[$k] = $info[$k] }
    $infoLine = ConvertTo-InfoLine $h
    $infoFile = Join-Path $paths.UserStateDir 'connection-info.txt'
    Set-Content -LiteralPath $infoFile -Value $infoLine -Encoding ASCII
    try { Set-Clipboard -Value $infoLine; $clip = '（已复制到剪贴板）' } catch { $clip = '' }
    Write-Host @"

================ 完成 ================
把下面这一行发给协助你的人（里面只有地址、用户名和主机公钥，没有任何密码或私钥）$clip：

$infoLine

也保存在 $infoFile
查看状态: 本脚本 status    撤销授权: 本脚本 revoke
"@
}

function Invoke-Status {
    $paths = Get-TnaPaths
    Say "tailnet-assist 目标端状态（Windows）"
    $ip = Get-TailscaleIp
    Say ("Tailscale: " + $(if ($ip) { $ip } elseif (Get-TailscaleExe) { '未连接' } else { '未安装' }))
    $svc = Get-Service sshd -ErrorAction SilentlyContinue
    Say ("OpenSSH 服务端: " + $(if ($svc) { "$($svc.Status) / $($svc.StartType)" } else { '未安装' }))
    foreach ($f in @($paths.UserKeys, $paths.AdminKeys)) {
        try {
            if (Test-Path -LiteralPath $f) {
                $ls = @(Get-Content -LiteralPath $f -Encoding UTF8 | Where-Object { $_ -match $MarkerPattern })
                Say "$f : $($ls.Count) 条 tailnet-assist 授权"
                foreach ($l in $ls) {
                    $exp = if ($l -match 'expiry-time="([0-9Z]+)"') { $Matches[1] } else { '不过期' }
                    Say "  $(($l -split ' ')[-1])  到期: $exp"
                }
            }
        } catch { Say "$f : 需要管理员权限才能查看" }
    }
    $exe = $paths.CuaExe
    if (Test-Path -LiteralPath $exe) { Say ("Cua Driver: " + ((& $exe status 2>&1 | Select-Object -First 1) -as [string])) } else { Say 'Cua Driver: 未安装' }
    $infoFile = Join-Path $paths.UserStateDir 'connection-info.txt'
    if (Test-Path -LiteralPath $infoFile) { Say "连接信息: $(Get-Content -LiteralPath $infoFile -Raw)" }
}

function Invoke-Revoke {
    $paths = Get-TnaPaths
    $lbl = if ($Label -ne 'operator') { Get-SafeLabel $Label } else { '' }
    $n = Remove-TnaLines -Path $paths.UserKeys -KeyLabel $lbl
    if (Test-UserIsAdminMember) {
        $r = Invoke-Elevated 'admin-revoke' @{ label = $lbl }
        $n += [int]$r.removed
    }
    Say "已删除 $n 条 tailnet-assist 授权，之后的新连接会被拒绝。"
    if ($n -gt 0) { Say '已经连着的会话不会自动断开；要立即断开，可以在 Tailscale 托盘里断开连接，或重启 sshd 服务。' }
}

function Invoke-Uninstall {
    if (-not (Confirm-Step '撤销全部授权并还原 tailnet-assist 做过的更改？')) { throw '已取消' }
    $paths = Get-TnaPaths
    $n = Remove-TnaLines -Path $paths.UserKeys -KeyLabel ''
    $r = Invoke-Elevated 'admin-uninstall' @{ removeOpenSSH = [bool]$RemoveOpenSSH }
    Say "已删除 $($n + [int]$r.removed) 条授权"
    $exe = $paths.CuaExe
    if (Test-Path -LiteralPath $exe) {
        & $exe autostart disable *> $null
        & $exe stop *> $null
        Say 'Cua Driver 已停止并取消自动启动（程序本身还在，可在 Cua 官方卸载说明里删除）'
    }
    $ts = Get-TailscaleExe
    if ($LogoutTailscale -and $ts) { & $ts logout; Say '已登出 Tailscale' }
    else { Say 'Tailscale 没动。要让本机离开网络：tailscale logout，或在 Tailscale 管理后台删除本设备。' }
    Remove-Item -LiteralPath (Join-Path $paths.UserStateDir 'connection-info.txt') -ErrorAction SilentlyContinue
    Say '完成。'
}

function Read-Request {
    if (-not $RequestFile) { throw 'internal action needs -RequestFile' }
    return (Get-Content -LiteralPath $RequestFile -Raw | ConvertFrom-Json)
}

if ($Action -eq '__lib') { return }

try {
    switch ($Action) {
        'setup' { Invoke-Setup }
        'status' { Invoke-Status }
        'revoke' { Invoke-Revoke }
        'uninstall' { Invoke-Uninstall }
        'admin-setup' { Invoke-AdminSetup (Read-Request) }
        'admin-revoke' { Invoke-AdminRevoke (Read-Request) }
        'admin-uninstall' { Invoke-AdminUninstall (Read-Request) }
    }
} catch {
    Write-Host "错误: $($_.Exception.Message)" -ForegroundColor Red
    if ($Action -like 'admin-*') { Start-Sleep -Seconds 8 }
    exit 1
}
