# This PS is a part of the WinConfig documentation
# https://noverse.dev/docs/win-config/security/windows-firewall
# https://github.com/nohuto
# https://discord.noverse.dev

[CmdletBinding(SupportsShouldProcess)]
param([switch]$apply, [switch]$reset, [switch]$outbound, [string]$managedGroup = 'Noverse Firewall')
$ErrorActionPreference = 'Stop'

# Parameters:

# Pattern: wildcard against Name/DisplayName/DisplayGroup/Group.
# Name/DisplayName/DisplayGroup/Group: wildcard match against that exact field.
# Direction: Inbound, Outbound, both
# Action: Allow or Block

$disableExistingRulePatterns = @(
  @{ Pattern = 'AllJoyn Router*'; Direction = @('Inbound', 'Outbound') },
  @{ Pattern = 'Cast to Device*'; Direction = @('Inbound', 'Outbound') },
  @{ Pattern = 'Cloud Identity*'; Direction = @('Inbound', 'Outbound') },
  @{ Pattern = 'Connected Devices Platform*'; Direction = @('Inbound', 'Outbound') },
  @{ Pattern = 'Connected User Experiences and Telemetry*'; Direction = @('Inbound', 'Outbound') },
  @{ Pattern = 'Core Networking - Teredo*'; Direction = 'Outbound' },
  @{ Pattern = 'Delivery Optimization*'; Direction = @('Inbound', 'Outbound') },
  @{ Pattern = 'DIAL protocol server*'; Direction = @('Inbound', 'Outbound') },
  @{ Pattern = 'File and Printer Sharing*'; Direction = @('Inbound', 'Outbound') },
  @{ Pattern = 'Core Networking*'; Direction = 'Inbound' },
  @{ Pattern = 'Microsoft Media Foundation Network*'; Direction = @('Inbound', 'Outbound') },
  @{ Pattern = 'mDNS*'; Direction = @('Inbound', 'Outbound') },
  @{ Pattern = 'Network Discovery*'; Direction = @('Inbound', 'Outbound') },
  @{ Pattern = 'Proximity sharing over TCP*'; Direction = @('Inbound', 'Outbound') },
  @{ Pattern = 'Recommended Troubleshooting Client*'; Direction = @('Inbound', 'Outbound') },
  @{ Pattern = 'Remote Assistance*'; Direction = @('Inbound', 'Outbound') },
  @{ Pattern = 'WFD ASP Coordination Protocol*'; Direction = @('Inbound', 'Outbound') },
  @{ Pattern = 'WFD Driver-only*'; Direction = @('Inbound', 'Outbound') },
  @{ Pattern = 'Wi-Fi*'; Direction = @('Inbound', 'Outbound') },
  @{ Pattern = 'Wireless Display*'; Direction = @('Inbound', 'Outbound') },
  @{ Pattern = 'Windows Device Management*'; Direction = @('Inbound', 'Outbound') },
  @{ Pattern = 'Windows Feature Experience Pack'; Direction = @('Inbound', 'Outbound') }
)

# Parameters:

# DisplayName: rule name
# Direction: Inbound or Outbound
# Action: Allow or Block
# Program: executable path (wildcards supported)
# Service: service name
# Protocol: TCP, UDP, ICMPv4, ICMPv6, Any
# LocalPort/RemotePort: port number, range, list, Any
# LocalAddress/RemoteAddress: IP, subnet, range, keyword, list, Any
# Package: app package family name
# InterfaceType: Any, Wireless, LAN, RemoteAccess
# Profile: Domain, Private, Public, Any (default)
# Enabled: True (default) or False
# Group: rule group (default $managedGroup)

$rules = @(
  # Outbound allow
  @{ DisplayName = 'Git Remote HTTPS'; Direction = 'Outbound'; Action = 'Allow'; Program = 'C:\Program Files\Git\mingw64\libexec\git-core\git-remote-https.exe'; Protocol = 'TCP'; RemotePort = @('443') },
  @{ DisplayName = 'Steam'; Direction = 'Outbound'; Action = 'Allow'; Program = 'C:\Program Files (x86)\Steam\steam.exe'; Protocol = 'TCP'; RemotePort = @('443') },
  @{ DisplayName = 'Cryptographic Services'; Direction = 'Outbound'; Action = 'Allow'; Program = '%SystemRoot%\System32\svchost.exe'; Service = 'CryptSvc'; Protocol = 'TCP'; RemotePort = @('80') },
  @{ DisplayName = 'svchost HTTP/S'; Direction = 'Outbound'; Action = 'Allow'; Program = '%SystemRoot%\System32\svchost.exe'; Protocol = 'TCP'; RemotePort = @('80', '443'); Enabled = 'False' },

  # Outbound block
  @{ DisplayName = 'Steam CEF'; Direction = 'Outbound'; Action = 'Block'; Program = 'C:\Program Files (x86)\Steam\bin\cef\cef.win64\steamwebhelper.exe' },

  # Inbound block
  @{ DisplayName = 'Spotify'; Direction = 'Inbound'; Action = 'Block'; Program = 'C:\Users\nohuto\AppData\Roaming\Spotify\Spotify.exe' },
  @{ DisplayName = 'Steam CEF'; Direction = 'Inbound'; Action = 'Block'; Program = 'C:\Program Files (x86)\Steam\bin\cef\cef.win64\steamwebhelper.exe' }
)

function get-enabledfirewallrules {
  Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -ErrorAction Stop | Where-Object { $_.Direction -in @('Inbound', 'Outbound') }
}

function convertto-stringarray {
  param([object]$value)

  if ($null -eq $value) { return @() }
  if ($value -is [System.Array]) {
      return @($value | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
  }
  $text = "$value".Trim()
  if (-not $text) { return @() }
  return @($text)
}

function test-rulevaluepattern {
  param(
      [object]$value,
      [object]$pattern
  )

  $patterns = @(convertto-stringarray $pattern)
  if (-not $patterns.Count) { return $true }

  $text = if ($null -eq $value) { '' } else { "$value" }
  foreach ($item in $patterns) {
      if ($text -like $item) { return $true }
  }
  return $false
}

function test-ruletextpattern {
  param(
      [Parameter(Mandatory)][object]$rule,
      [Parameter(Mandatory)][object]$pattern
  )

  return (
      (test-rulevaluepattern -value $rule.Name -pattern $pattern) -or
      (test-rulevaluepattern -value $rule.DisplayName -pattern $pattern) -or
      (test-rulevaluepattern -value $rule.DisplayGroup -pattern $pattern) -or
      (test-rulevaluepattern -value $rule.Group -pattern $pattern)
  )
}

function test-rulepattern {
  param(
      [Parameter(Mandatory)][object]$rule,
      [Parameter(Mandatory)][object]$pattern
  )

  if ($pattern -is [string]) {
      return (test-ruletextpattern -rule $rule -pattern $pattern)
  }

  if ($pattern -isnot [hashtable]) {
      throw 'Disable patterns must be strings or hashtables'
  }

  foreach ($key in $pattern.Keys) {
      if ($key -eq 'Pattern') {
          if (-not (test-ruletextpattern -rule $rule -pattern $pattern[$key])) {
              return $false
          }
          continue
      }

      if ($key -notin @('Name', 'DisplayName', 'DisplayGroup', 'Group', 'Direction', 'Action')) {
          throw "Unsupported disable pattern key: $key"
      }
      if (-not (test-rulevaluepattern -value $rule.$key -pattern $pattern[$key])) {
          return $false
      }
  }
  return $true
}

function test-rulematchesdisablepattern {
  param([Parameter(Mandatory)][object]$rule)

  foreach ($pattern in $disableExistingRulePatterns) {
      if (test-rulepattern -rule $rule -pattern $pattern) {
          return $true
      }
  }
  return $false
}

function disable-existingrules {
  $rulesToDisable = @(get-enabledfirewallrules | Where-Object { test-rulematchesdisablepattern -rule $_ })
  if (-not $rulesToDisable.Count) {
      Write-Host 'No enabled firewall rules matched disable patterns'
      return
  }

  if ($PSCmdlet.ShouldProcess("$($rulesToDisable.Count) enabled firewall rules", 'Disable')) {
      $ruleNames = @($rulesToDisable | Select-Object -ExpandProperty Name -Unique)
      foreach ($ruleName in $ruleNames) {
          Disable-NetFirewallRule -Name $ruleName -ErrorAction Stop | Out-Null
      }
  }

  $rulesToDisable | Sort-Object Direction, DisplayGroup, DisplayName | Select-Object Direction, DisplayGroup, Name, DisplayName | Format-Table -AutoSize
}

function remove-managedrules {
  $existing = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
      Where-Object { $_.DisplayGroup -eq $managedGroup -or $_.Group -eq $managedGroup })
  if (-not $existing.Count) {
      return
  }

  if ($PSCmdlet.ShouldProcess("$($existing.Count) managed firewall rules", 'Remove')) {
      $existing | Remove-NetFirewallRule
  }
}

function resolve-ruleprograms {
  param([Parameter(Mandatory)][string]$program)

  $expandedProgram = [Environment]::ExpandEnvironmentVariables($program)
  $wildcardChars = '*?['
  $hasWildcard = $expandedProgram.IndexOfAny($wildcardChars.ToCharArray()) -ge 0

  if ($hasWildcard) {
      return @(Get-ChildItem -Path $expandedProgram -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
  }

  if (Test-Path -LiteralPath $expandedProgram) {
      return @((Resolve-Path -LiteralPath $expandedProgram).Path)
  }

  return @()
}

function add-managedrules {
  remove-managedrules

  foreach ($rule in $rules) {
      $baseParams = @{} + $rule
      if (-not $baseParams.ContainsKey('Group')) { $baseParams.Group = $managedGroup }
      if (-not $baseParams.ContainsKey('Profile')) { $baseParams.Profile = 'Any' }
      if (-not $baseParams.ContainsKey('Enabled')) { $baseParams.Enabled = 'True' }

      if ($baseParams.ContainsKey('Program')) {
          $resolvedPrograms = @(resolve-ruleprograms -program $baseParams.Program)
          if (-not $resolvedPrograms.Count) {
              Write-Host "Missing EXE: $($baseParams.Program)"
              continue
          }

          foreach ($resolvedProgram in $resolvedPrograms) {
              $params = @{} + $baseParams
              $params.Program = $resolvedProgram
              if ($PSCmdlet.ShouldProcess($params.DisplayName, 'Create firewall rule')) {
                  New-NetFirewallRule @params | Out-Null
              }
          }
          continue
      }

      if ($PSCmdlet.ShouldProcess($baseParams.DisplayName, 'Create firewall rule')) {
          New-NetFirewallRule @baseParams | Out-Null
      }
  }
}

function set-blockedprofiles {
  if ($PSCmdlet.ShouldProcess('Domain, Private, Public firewall profiles', 'Set inbound/outbound block defaults')) {
      Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block -NotifyOnListen False -AllowInboundRules True -AllowLocalFirewallRules True -AllowLocalIPsecRules True -AllowUnicastResponseToMulticast False -EnableStealthModeForIPsec True -LogFileName '%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log' -LogMaxSizeKilobytes 16384 -LogBlocked True -LogIgnored True
  }
}

function set-outboundprofiles {
  if ($PSCmdlet.ShouldProcess('Domain, Private, Public firewall profiles', 'Allow outbound and block inbound without changing existing rules')) {
      Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen False -AllowInboundRules False -AllowLocalFirewallRules True -AllowLocalIPsecRules True -AllowUnicastResponseToMulticast False -EnableStealthModeForIPsec True -LogFileName '%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log' -LogMaxSizeKilobytes 16384 -LogBlocked True -LogIgnored True
  }
}

function reset-firewall {
  if ($PSCmdlet.ShouldProcess('Windows Firewall policy', 'Reset to Windows defaults')) {
      netsh advfirewall reset
      if ($LASTEXITCODE -ne 0) {
          throw "netsh advfirewall reset failed with exit code $LASTEXITCODE"
      }
  }
}

$selectedFlags = @(@($apply, $reset, $outbound) | Where-Object { $_.IsPresent })
if ($selectedFlags.Count -ne 1) {
    throw 'Use one flag (-apply, -reset, -outbound)'
}

if ($reset) {
    reset-firewall
    return
}

if ($outbound) {
    set-outboundprofiles
    return
}

disable-existingrules
add-managedrules
set-blockedprofiles
