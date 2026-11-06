param([switch]$Launched, [switch]$TestConnection, [switch]$AuthTrace)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        # Encode the entire command so spaces, apostrophes and shell characters
        # in a download directory cannot become executable command text.
        $literalPath = $PSCommandPath.Replace("'", "''")
        $command = "& '$literalPath' -Launched"
        if ($TestConnection) { $command += " -TestConnection" }
        if ($AuthTrace) { $command += " -AuthTrace" }
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $hostPath = Join-Path $PSHOME 'powershell.exe'
        $child = Start-Process -FilePath $hostPath -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded) -Wait -PassThru
        exit $child.ExitCode
    } catch {
        Write-Host ('Administrator authorization was canceled or failed: ' + $_.Exception.Message) -ForegroundColor Red
        exit 1
    }
}
$traceChangedLogs=@()
try {
    if ($AuthTrace) { $TestConnection=$true }
    $lines = [System.Collections.Generic.List[string]]::new()
    function Record($title, $data) {
        $lines.Add("`r`n=== $title ===")
        $lines.Add(($data | Format-List | Out-String -Width 180).TrimEnd())
    }
    $os = Get-CimInstance Win32_OperatingSystem
    Record 'Windows' ([pscustomobject]@{Caption=$os.Caption; Version=$os.Version; Build=$os.BuildNumber; CollectedAt=(Get-Date -Format o)})
    Record 'Services (read-only)' (Get-Service IKEEXT,PolicyAgent,RasMan,KeyIso | Select-Object Name,Status,StartType)
    $profiles = @()
    foreach ($scope in @($false,$true)) {
        try {
            $found = if ($scope) { Get-VpnConnection -AllUserConnection } else { Get-VpnConnection }
            $profiles += @($found | Where-Object Name -Like 'SynoVPN-*')
        } catch { Record 'Profile query error' $_.Exception.Message }
    }
    if ($AuthTrace) {
        Record 'Trace scope' 'RSA signing is tested only as the elevated administrator, not as the IKEEXT service identity. No private key or signature is exported.'
        $machineCerts=@(Get-ChildItem Cert:\LocalMachine\My | Where-Object Issuer -Like '*SynoVPN*')
        foreach ($cert in $machineCerts) {
            $rsa=$null
            try {
                $rsa=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
                if (!$rsa) { throw 'No usable RSA private key returned.' }
                $info=[ordered]@{Subject=$cert.Subject;Thumbprint=$cert.Thumbprint;KeyType=$rsa.GetType().FullName;CertificateSignatureAlgorithm=$cert.SignatureAlgorithm.Value;KeySize=$rsa.KeySize}
                if ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
                    $info.Provider=$rsa.CspKeyContainerInfo.ProviderName
                    $info.KeyNumber=[string]$rsa.CspKeyContainerInfo.KeyNumber
                    $info.MachineKeyStore=$rsa.CspKeyContainerInfo.MachineKeyStore
                    $info.Accessible=$rsa.CspKeyContainerInfo.Accessible
                } elseif ($rsa -is [System.Security.Cryptography.RSACng]) {
                    $info.Provider=$rsa.Key.Provider.Provider
                    $info.MachineKeyStore=$rsa.Key.IsMachineKey
                    $info.KeyUsage=[string]$rsa.Key.KeyUsage
                }
                $challenge=New-Object byte[] 32
                $rng=[System.Security.Cryptography.RandomNumberGenerator]::Create()
                try { $rng.GetBytes($challenge) } finally { $rng.Dispose() }
                $signature=$rsa.SignData($challenge,[System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                $pub=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
                try { $info.AdminSignVerify=$pub.VerifyData($challenge,$signature,[System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1) } finally { $pub.Dispose() }
                Record 'Private-key access probe (administrator only)' ([pscustomobject]$info)
            } catch { Record 'Private-key access probe failed' ([pscustomobject]@{Subject=$cert.Subject;Error=$_.Exception.Message;HResult=$_.Exception.HResult}) }
            finally { if ($rsa) { $rsa.Dispose() } }
        }
        foreach ($channel in @('Microsoft-Windows-CAPI2/Operational','Microsoft-Windows-IKEEXT/Operational','Microsoft-Windows-RasClient/Operational')) {
            try {
                $channelInfo=Get-WinEvent -ListLog $channel -ErrorAction Stop
                if (!$channelInfo.IsEnabled) {
                    # Restore the previous state immediately after the one dial.
                    $traceChangedLogs+= $channel
                    $channelInfo.IsEnabled=$true
                    $channelInfo.SaveChanges()
                }
                Record 'Trace channel available' $channel
            } catch { Record 'Trace channel unavailable' ([pscustomobject]@{Channel=$channel;Error=$_.Exception.Message}) }
        }
    }
    if ($TestConnection) {
        if (!$profiles.Count) { throw 'No SynoVPN connection found on this computer.' }
        Write-Host 'Select the failing connection for one test dial:'
        for ($i=0;$i -lt $profiles.Count;$i++) { Write-Host (($i+1).ToString()+': '+$profiles[$i].Name) }
        if ($profiles.Count -eq 1) { $selection='1'; Write-Host 'Only one SynoVPN connection; selecting 1 automatically.' } else { $selection=Read-Host 'Connection number' }
        $number=0
        if (![int]::TryParse($selection,[ref]$number) -or $number -lt 1 -or $number -gt $profiles.Count) { throw 'Invalid selection. No connection attempted.' }
        $target=$profiles[$number-1]
        if ($target.ConnectionStatus -eq 'Connected') { throw 'Selected VPN is already connected. No test dial performed.' }
        Record 'Test start (selected profile only)' ([pscustomobject]@{Name=$target.Name;Time=(Get-Date -Format o)})
        $traceStart=Get-Date
        # No username/password, credential export, profile changes or redial loop.
        $previousPreference=$ErrorActionPreference
        try {
            $ErrorActionPreference='Continue'
            $dialOutput = & "$env:SystemRoot\System32\rasdial.exe" $target.Name 2>&1
            $dialExit=$LASTEXITCODE
        } finally { $ErrorActionPreference=$previousPreference }
        Record 'RAS dial result' ([pscustomobject]@{Name=$target.Name;ExitCode=$dialExit;FinishedAt=(Get-Date -Format o);Output=($dialOutput | Out-String)})
        if ($dialExit -eq 0) { Write-Host 'VPN connected successfully; it remains connected until you disconnect it.' }
        if ($AuthTrace) {
            Start-Sleep -Seconds 3
            $traceEnd=Get-Date
            foreach ($channel in @('Microsoft-Windows-CAPI2/Operational','Microsoft-Windows-IKEEXT/Operational','Microsoft-Windows-RasClient/Operational','Application','System')) {
                $filter=@{LogName=$channel;StartTime=$traceStart;EndTime=$traceEnd}
                $events=@(Get-WinEvent -FilterHashtable $filter -MaxEvents 100 -ErrorAction SilentlyContinue)
                if ($channel -eq 'Application' -or $channel -eq 'System') { $events=@($events | Where-Object ProviderName -Match 'Ras|IKE|RemoteAccess|CAPI|Schannel') }
                Record ('Authentication events: '+$channel) @($events | Select-Object -First 30 | ForEach-Object {
                    $eventXml=$_.ToXml()
                    if ($eventXml.Length -gt 12000) { $eventXml=$eventXml.Substring(0,12000)+' [truncated]' }
                    [pscustomobject]@{Time=$_.TimeCreated;Provider=$_.ProviderName;EventID=$_.Id;XML=$eventXml}
                })
            }
            foreach ($channel in $traceChangedLogs) {
                try { $state=Get-WinEvent -ListLog $channel -ErrorAction Stop; $state.IsEnabled=$false; $state.SaveChanges() }
                catch { Record 'Log-state restore failed' ([pscustomobject]@{Channel=$channel;Error=$_.Exception.Message}) }
            }
        }

    }
    Record 'SynoVPN profiles' ($profiles | Select-Object Name,ServerAddress,TunnelType,AuthenticationMethod,AllUserConnection,ConnectionStatus,SplitTunneling,EncryptionLevel,MachineCertificateIssuerFilter,MachineCertificateEKUFilter,IPsecCustomPolicy)
    foreach ($vpn in $profiles) {
        try {
            $answers = @(Resolve-DnsName -Name $vpn.ServerAddress -Type A -ErrorAction Stop | Select-Object Type,IPAddress)
            Record ('DNS for '+$vpn.ServerAddress) $answers
            if (@($answers | Where-Object { $_.IPAddress -match '^198\.(18|19)\.' }).Count) {
                Record 'WARNING: VPN endpoint resolves to benchmark/Fake-IP range' '198.18.0.0/15 is not a public VPN endpoint. Check local/router proxy Fake-IP and TUN interception. Exempt the VPN domain from Fake-IP and use a direct route to the real endpoint. This is a diagnostic clue, not proof of a specific proxy product.'
            }
            Record ('IPsec policy for '+$vpn.Name) $vpn.IPsecCustomPolicy
        }
        catch { Record 'DNS error' $_.Exception.Message }
    }
    $certs = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -Like '*SynoVPN*' })
    Record 'Machine device certificates (metadata only)' ($certs | Select-Object Subject,Issuer,Thumbprint,NotBefore,NotAfter,HasPrivateKey,@{Name='EKU';Expression={($_.EnhancedKeyUsageList | ForEach-Object {if ($_.ObjectId) {[string]$_.ObjectId} else {[string]$_.Value}}) -join ','}})
    Record 'SynoVPN machine trust roots (metadata only)' (Get-ChildItem Cert:\LocalMachine\Root | Where-Object Subject -Like '*SynoVPN*' | Select-Object Subject,Thumbprint,NotAfter)
    $recent = @(Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='RasClient';StartTime=(Get-Date).AddHours(-2)} -MaxEvents 100 -ErrorAction SilentlyContinue)
    $errors = foreach ($event in $recent) {
        $xml=[xml]$event.ToXml()
        $data=@{}
        foreach ($item in $xml.Event.EventData.Data) { if($item.Name) { $data[[string]$item.Name]=[string]$item.'#text' } }
        if($data['ConnectionName'] -like 'SynoVPN-*') {
            [pscustomobject]@{Time=$event.TimeCreated;EventID=$event.Id;ConnectionName=$data['ConnectionName'];ErrorCode=$data['ErrorCode']}
        }
    }
    Record 'Recent SynoVPN RasClient events (no event messages or usernames)' $errors
    $prefix=if($AuthTrace){'SynoVPN-auth-trace-'}else{'SynoVPN-diagnostics-'}
    $report=Join-Path $PSScriptRoot ($prefix+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.txt')
    [System.IO.File]::WriteAllLines($report,$lines,[System.Text.UTF8Encoding]::new($true))
    Write-Host ('Report saved: '+$report) -ForegroundColor Green
    if ($TestConnection) { Write-Host 'One selected connection tested; no profile/certificate settings changed or keys/passwords exported.' } else { Write-Host 'Read-only: no settings changed, no keys/passwords exported, no connection attempted.' }
    Start-Process -FilePath notepad.exe -ArgumentList ('"'+$report+'"')
} catch {
    Write-Host ('Diagnostics failed: '+$_.Exception.Message) -ForegroundColor Red
    exit 1
} finally {
    foreach ($channel in $traceChangedLogs) {
        try { $state=Get-WinEvent -ListLog $channel -ErrorAction Stop; $state.IsEnabled=$false; $state.SaveChanges() } catch { Write-Host ('Could not restore log state: '+$channel) -ForegroundColor Yellow }
    }
    if ($Launched) { [void](Read-Host 'Press Enter to close this window') }
}
