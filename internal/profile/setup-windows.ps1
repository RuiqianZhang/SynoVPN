#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$cfg = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'certificate.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$serverCAPath = Join-Path $PSScriptRoot 'SynoVPN-Server-CA.cer'
$clientCAPath = Join-Path $PSScriptRoot 'SynoVPN-Client-CA.cer'
$serverCA = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($serverCAPath)
$clientCA = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($clientCAPath)
Write-Host ('VPN server: ' + $cfg.server)
Write-Host ('Server CA SHA256: ' + $serverCA.GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA256))
Write-Host ('Device CA SHA256: ' + $clientCA.GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA256))
if ((Read-Host 'Trust these CAs and install this device certificate? Type YES') -cne 'YES') { exit 1 }
$existing = Get-VpnConnection -Name $cfg.name -AllUserConnection -ErrorAction SilentlyContinue
if ($existing) { throw 'This VPN profile already exists. Remove it explicitly before importing again.' }
$conflicts = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -eq $clientCA.Subject -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) })
if ($conflicts.Count) { throw 'Another device certificate from this NAS is installed. Revoke and explicitly remove the old certificate first to avoid selecting the wrong device identity.' }
Import-Certificate -FilePath $serverCAPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Import-Certificate -FilePath $clientCAPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
$importPassword = ConvertTo-SecureString $cfg.certificate_import_password -AsPlainText -Force
# Imported keys are not marked Exportable. The downloaded P12 can still be copied.
Import-PfxCertificate -FilePath (Join-Path $PSScriptRoot 'SynoVPN-Device.p12') -CertStoreLocation Cert:\LocalMachine\My -Password $importPassword | Out-Null
Add-VpnConnection -Name $cfg.name -ServerAddress $cfg.server -TunnelType Ikev2 -AuthenticationMethod MachineCertificate -MachineCertificateIssuerFilter $clientCA -MachineCertificateEKUFilter '1.3.6.1.5.5.7.3.2' -EncryptionLevel Required -SplitTunneling -AllUserConnection | Out-Null
Set-VpnConnectionIPsecConfiguration -ConnectionName $cfg.name -AllUserConnection -AuthenticationTransformConstants SHA256128 -CipherTransformConstants AES256 -EncryptionMethod AES256 -IntegrityCheckMethod SHA256 -DHGroup Group14 -PfsGroup None -Force
foreach ($route in $cfg.routes) { Add-VpnConnectionRoute -ConnectionName $cfg.name -DestinationPrefix $route -AllUserConnection | Out-Null }
Write-Host 'Certificate VPN installed. Connect from Windows VPN settings. No VPN username or password is required.'
Start-Process 'ms-settings:network-vpn'
