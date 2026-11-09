#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$cfg = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'certificate.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$vpn = Get-VpnConnection -Name $cfg.name -AllUserConnection -ErrorAction Stop
if ($vpn.ConnectionStatus -ne 'Disconnected') { throw 'Disconnect this VPN before updating its routes.' }
# Only the selected SynoVPN profile is changed. Re-running repairs partial updates.
Set-VpnConnection -Name $cfg.name -AllUserConnection -SplitTunneling $true -Force
foreach ($route in @($vpn.Routes)) {
    if ($route.DestinationPrefix -notin $cfg.routes) {
        Remove-VpnConnectionRoute -ConnectionName $cfg.name -DestinationPrefix $route.DestinationPrefix -AllUserConnection -Confirm:$false | Out-Null
    }
}
foreach ($route in $cfg.routes) {
    if ($route -notin @($vpn.Routes | ForEach-Object { $_.DestinationPrefix })) {
        Add-VpnConnectionRoute -ConnectionName $cfg.name -DestinationPrefix $route -AllUserConnection | Out-Null
    }
}
Write-Host 'VPN routes updated. Reconnect from Windows VPN settings.'
