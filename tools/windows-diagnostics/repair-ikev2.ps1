param([switch]$Launched)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        # Encode the entire command so spaces, apostrophes and shell characters
        # in a download directory cannot become executable command text.
        $literalPath = $PSCommandPath.Replace("'", "''")
        $command = "& '$literalPath' -Launched"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $hostPath = Join-Path $PSHOME 'powershell.exe'
        $child = Start-Process -FilePath $hostPath -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded) -Wait -PassThru
        exit $child.ExitCode
    } catch {
        Write-Host ('Administrator authorization was canceled or failed: ' + $_.Exception.Message) -ForegroundColor Red
        exit 1
    }
}
try {
    $os=Get-CimInstance Win32_OperatingSystem
    $build=[int]$os.BuildNumber
    if ($os.ProductType -ne 1 -or $build -lt 19041 -or $build -ge 22000) { throw 'This recovery is only for Windows 10 version 2004 or later, not Windows 11 or Windows Server.' }
    # Fail closed if connection state cannot be read. Never disrupt a known VPN.
    $vpnProfiles=@(Get-VpnConnection -ErrorAction Stop)+@(Get-VpnConnection -AllUserConnection -ErrorAction Stop)
    if (@($vpnProfiles | Where-Object ConnectionStatus -eq 'Connected').Count) { throw 'A VPN is connected. Disconnect all VPN connections before this recovery.' }
    $devices=@(Get-PnpDevice -Class Net -PresentOnly -ErrorAction Stop | Where-Object { $_.InstanceId -match '(^|\\)MS_AGILEVPNMINIPORT($|\\)' })
    if ($devices.Count -ne 1) { throw 'Cannot uniquely identify the Windows IKEv2 WAN Miniport. No device was changed.' }
    $device=$devices[0]
    Write-Host ('Restarting only: '+$device.FriendlyName)
    Write-Host ('Device: '+$device.InstanceId)
    $result=& "$env:SystemRoot\System32\pnputil.exe" /restart-device $device.InstanceId 2>&1
    $status=$LASTEXITCODE
    $log=Join-Path $PSScriptRoot ('SynoVPN-IKEv2-recovery-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.txt')
    @('Time: '+(Get-Date -Format o),'Device: '+$device.InstanceId,'Exit code: '+$status,($result | Out-String)) | Set-Content -LiteralPath $log -Encoding UTF8
    $result | Out-Host
    Write-Host ('Log saved: '+$log)
    if ($status -eq 3010) { Write-Host 'Windows requests a reboot. Restart the PC manually, then retry the VPN.' -ForegroundColor Yellow }
    elseif ($status -ne 0) { throw ('Device restart failed (exit '+$status+'). No uninstall or network reset was attempted.') }
    else { Write-Host 'IKEv2 adapter restarted. Retry the VPN, or run test-connection.cmd to capture the result. This is a recovery attempt, not a confirmed fix.' -ForegroundColor Green }
} catch {
    Write-Host ('Recovery stopped: '+$_.Exception.Message) -ForegroundColor Red
    exit 1
} finally {
    if ($Launched) { [void](Read-Host 'Press Enter to close this window') }
}
