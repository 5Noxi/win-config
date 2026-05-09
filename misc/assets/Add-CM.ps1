$nvfolder  = "$env:localappdata\Noverse"
$gen = Join-Path $nvfolder "HashGen.ps1"
$local = Join-Path $home "Downloads\HashGen.ps1"
if (!(Test-Path $nvfolder)) { New-Item -ItemType Directory -Path $nvfolder -Force | Out-Null }

if (Test-Path -LiteralPath $local) {
    Move-Item -LiteralPath $local -Destination $gen -Force
} else {
    try {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/nohuto/hash-gen/main/HashGen.ps1" -OutFile $gen -UseBasicParsing
    } catch {
        throw "Failed to download HashGen.ps1: $($_.Exception.Message)"
    }
}

$extended = "HashGen.ContextMenu"
$shell = Join-Path "HKCU:\Software\Classes\$extended" "shell"

foreach ($old in @(
        "HKCU:\Software\Classes\*\shell\Hashes",
        "HKCU:\Software\Classes\Directory\shell\Hashes",
        "HKCU:\Software\Classes\$extended"
    )) {
    if (Test-Path -LiteralPath $old) {
        Remove-Item -LiteralPath $old -Recurse -Force
    }
}

New-Item -Path $shell -Force | Out-Null

foreach ($entry in @(
        @{Key='All'; Label='All Hashes'; Argument='All'},
        @{Key='MD5'; Label='MD5'; Argument='MD5'},
        @{Key='SHA1'; Label='SHA1'; Argument='SHA1'},
        @{Key='SHA256'; Label='SHA256'; Argument='SHA256'},
        @{Key='SHA384'; Label='SHA384'; Argument='SHA384'},
        @{Key='SHA512'; Label='SHA512'; Argument='SHA512'},
        @{Key='MACTripleDES'; Label='MACTripleDES'; Argument='MACTripleDES'},
        @{Key='RIPEMD160'; Label='RIPEMD160'; Argument='RIPEMD160'}
    )) {
    $entry = Join-Path $shell $entry.Key
    New-Item -Path $entry -Force | Out-Null
    Set-ItemProperty -LiteralPath $entry -Name "MUIVerb" -Value $entry.Label

    $cmdPath = Join-Path $entry "command"
    New-Item -Path $cmdPath -Force | Out-Null
    $command = ('powershell -NoExit -file "{0}" -nvstringin "%1" -Algorithm {1}' -f $gen, $entry.Argument)
    Set-ItemProperty -LiteralPath $cmdPath -Name "(Default)" -Value $command
}

foreach ($menu in @(
        "HKCU:\Software\Classes\*\shell\Hashes",
        "HKCU:\Software\Classes\Directory\shell\Hashes"
    )) {
    New-Item -Path $menu -Force | Out-Null
    Set-ItemProperty -LiteralPath $menu -Name "MUIVerb" -Value "Hashes"
    Set-ItemProperty -LiteralPath $menu -Name "ExtendedSubCommandsKey" -Value $extended
}
