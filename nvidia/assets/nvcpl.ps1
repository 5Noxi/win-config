# https://discord.gg/E2ybG4j9jU
$ErrorActionPreference = "silentlycontinue"
Set-Service -Name "NVDisplay.ContainerLocalSystem" -StartupType Disabled
spsv -Name "NVDisplay.ContainerLocalSystem" -Force
Set-Service -Name 'NvTelemetryContainer' -StartupType Disabled
spsv -Name 'NvTelemetryContainer' -Force
$nvroam = "$env:appdata\Noverse"
$desktop = [Environment]::GetFolderPath('Desktop')
if (-not (Test-Path $nvroam)) {New-Item -ItemType Directory -Path $nvroam | Out-Null}
iwr -Uri "https://github.com/5Noxi/Files/releases/download/driver/nvcplui.exe" -OutFile "$nvroam\nvcplui.exe" | Out-Null
iwr -Uri "https://github.com/5Noxi/Files/releases/download/driver/Nvcpl.ico" -OutFile "$nvroam\Nvcpl.ico" | Out-Null
$nvpsnvcpl = "$nvroam\NV-nvcpl.ps1"
$nvcplcon = @"
`$ErrorActionPreference = "silentlycontinue"
`$nvsrv='NVDisplay.ContainerLocalSystem','NvContainerLocalSystem'
foreach (`$s in `$nvsrv){if(gsv `$s){Set-Service `$s -StartupType Manual
if ((gsv `$s).Status -ne 'Running'){sasv `$s}}}
saps -FilePath "$nvroam\nvcplui.exe" -Wait
foreach (`$s in `$nvsrv){if(gsv `$s){if((gsv `$s).Status -eq 'Running'){spsv `$s -Force}
Set-Service `$s -StartupType Disabled}}
"@
$nvcplcon | Set-Content -Encoding ASCII -Path $nvpsnvcpl | Out-Null
$nvsh = New-Object -ComObject WScript.Shell
$shortcut = $nvsh.CreateShortcut("$desktop\Nvcpl.lnk")
$shortcut.TargetPath = "powershell.exe"
$shortcut.Arguments = "-ExecutionPolicy Unrestricted -WindowStyle Hidden -File `"$nvpsnvcpl`""
$shortcut.WorkingDirectory = $nvroam
$shortcut.IconLocation = "$nvroam\Nvcpl.ico"
$shortcut.Save()