if (-not ("CursorRefreshEx.NativeMethods" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace CursorRefreshEx {
    public static class NativeMethods {
        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool SystemParametersInfoW(
            uint uiAction,
            uint uiParam,
            IntPtr pvParam,
            uint fWinIni
        );
    }

    public static class CursorColorizer {
        private static ushort ReadUInt16(byte[] data, int offset) {
            return BitConverter.ToUInt16(data, offset);
        }

        private static uint ReadUInt32(byte[] data, int offset) {
            return BitConverter.ToUInt32(data, offset);
        }

        public static void RecolorCursorFile(string path, byte targetR, byte targetG, byte targetB) {
            var data = File.ReadAllBytes(path);
            if (ReadUInt16(data, 2) != 2) {
                return;
            }

            var count = ReadUInt16(data, 4);
            for (var i = 0; i < count; i++) {
                var dirOffset = 6 + (i * 16);
                var imageOffset = (int)ReadUInt32(data, dirOffset + 12);
                var biSize = (int)ReadUInt32(data, imageOffset);
                var biWidth = (int)ReadUInt32(data, imageOffset + 4);
                var biHeight = (int)ReadUInt32(data, imageOffset + 8) / 2;
                var biBitCount = ReadUInt16(data, imageOffset + 14);

                if (biBitCount != 32) {
                    continue;
                }

                var pixelOffset = imageOffset + biSize;
                var counts = new Dictionary<int, int>();

                for (var y = 0; y < biHeight; y++) {
                    var rowOffset = pixelOffset + (y * biWidth * 4);
                    for (var x = 0; x < biWidth; x++) {
                        var offset = rowOffset + (x * 4);
                        var b = data[offset];
                        var g = data[offset + 1];
                        var r = data[offset + 2];
                        var a = data[offset + 3];

                        if (a == 0 || (r == 0 && g == 0 && b == 0)) {
                            continue;
                        }

                        var key = r | (g << 8) | (b << 16);
                        int current;
                        if (counts.TryGetValue(key, out current)) {
                            counts[key] = current + 1;
                        } else {
                            counts[key] = 1;
                        }
                    }
                }

                if (counts.Count == 0) {
                    continue;
                }

                var sourceKey = 0;
                var maxCount = -1;
                foreach (var entry in counts) {
                    if (entry.Value > maxCount) {
                        sourceKey = entry.Key;
                        maxCount = entry.Value;
                    }
                }

                var sourceR = sourceKey & 0xFF;
                var sourceG = (sourceKey >> 8) & 0xFF;
                var sourceB = (sourceKey >> 16) & 0xFF;

                for (var y = 0; y < biHeight; y++) {
                    var rowOffset = pixelOffset + (y * biWidth * 4);
                    for (var x = 0; x < biWidth; x++) {
                        var offset = rowOffset + (x * 4);
                        var b = data[offset];
                        var g = data[offset + 1];
                        var r = data[offset + 2];
                        var a = data[offset + 3];

                        if (a == 0 || (r == 0 && g == 0 && b == 0)) {
                            continue;
                        }

                        double factorSum = 0;
                        var factorCount = 0;

                        if (sourceR > 0) {
                            factorSum += (double)r / sourceR;
                            factorCount++;
                        }
                        if (sourceG > 0) {
                            factorSum += (double)g / sourceG;
                            factorCount++;
                        }
                        if (sourceB > 0) {
                            factorSum += (double)b / sourceB;
                            factorCount++;
                        }

                        if (factorCount == 0) {
                            continue;
                        }

                        var factor = factorSum / factorCount;
                        data[offset] = ClampToByte(targetB * factor);
                        data[offset + 1] = ClampToByte(targetG * factor);
                        data[offset + 2] = ClampToByte(targetR * factor);
                    }
                }
            }

            File.WriteAllBytes(path, data);
        }

        private static byte ClampToByte(double value) {
            if (value <= 0) return 0;
            if (value >= 255) return 255;
            return (byte)Math.Round(value);
        }
    }
}
"@
}

$cursorType = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Accessibility" -Name CursorType -ErrorAction SilentlyContinue).CursorType
$cursorColor = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Accessibility" -Name CursorColor -ErrorAction SilentlyContinue).CursorColor

$cursorDir = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Cursors"
$templateDir = Join-Path $cursorDir "NoverseTemplates"
$cursorFiles = @(
    "arrow_eoa.cur",
    "busy_eoa.cur",
    "cross_eoa.cur",
    "ew_eoa.cur",
    "helpsel_eoa.cur",
    "ibeam_eoa.cur",
    "link_eoa.cur",
    "move_eoa.cur",
    "nesw_eoa.cur",
    "ns_eoa.cur",
    "nwse_eoa.cur",
    "pen_eoa.cur",
    "person_eoa.cur",
    "pin_eoa.cur",
    "unavail_eoa.cur",
    "up_eoa.cur",
    "wait_eoa.cur"
)

if ($cursorType -eq 6 -and $null -ne $cursorColor -and (Test-Path $cursorDir)) {
    New-Item -Path $templateDir -ItemType Directory -Force | Out-Null

    foreach ($name in $cursorFiles) {
        $source = Join-Path $cursorDir $name
        $template = Join-Path $templateDir $name
        if ((Test-Path $source) -and -not (Test-Path $template)) {
            Copy-Item -Path $source -Destination $template -Force
        }
    }

    $targetR = [byte]($cursorColor -band 0xFF)
    $targetG = [byte](($cursorColor -shr 8) -band 0xFF)
    $targetB = [byte](($cursorColor -shr 16) -band 0xFF)

    foreach ($name in $cursorFiles) {
        $template = Join-Path $templateDir $name
        $target = Join-Path $cursorDir $name

        if (Test-Path $template) {
            Copy-Item -Path $template -Destination $target -Force
            [CursorRefreshEx.CursorColorizer]::RecolorCursorFile($target, $targetR, $targetG, $targetB)
        }
    }
}

$SPI_SETCURSORS = 0x0057
$SPIF_SENDCHANGE = 0x0002

if (-not [CursorRefreshEx.NativeMethods]::SystemParametersInfoW($SPI_SETCURSORS, 0, [IntPtr]::Zero, $SPIF_SENDCHANGE)) {
    $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "SPI_SETCURSORS failed with Win32 error $lastError."
}
