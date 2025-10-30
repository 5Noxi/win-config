# SMB Configuration

SMB Client -> Outbound connections
> https://learn.microsoft.com/en-us/powershell/module/smbshare/set-smbclientconfiguration?view=windowsserver2025-ps
SMB Server -> Inbound connections
> https://learn.microsoft.com/en-us/powershell/module/smbshare/set-smbserverconfiguration?view=windowsserver2025-ps

```ps
Set-SmbClientConfiguration -EnableBandwidthThrottling $false
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\DisableBandwidthThrottling	Type: REG_DWORD, Length: 4, Data: 1

Set-SmbClientConfiguration -EnableLargeMtu $true
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\DisableLargeMtu	Type: REG_DWORD, Length: 4, Data: 0
```

```ps
Set-SmbClientConfiguration -RequireSecuritySignature $true
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature	Type: REG_DWORD, Length: 4, Data: 1

Set-SmbClientConfiguration -EnableSecuritySignature $true
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\enablesecuritysignature	Type: REG_DWORD, Length: 4, Data: 1

Set-SmbClientConfiguration -EncryptionCiphers "AES_256_GCM, AES_256_CCM"
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\CipherSuiteOrder	Type: REG_MULTI_SZ, Length: 52, Data: AES_256_GCM, AES_256_CCM, 

Set-SmbServerConfiguration -RequireSecuritySignature $true
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature	Type: REG_DWORD, Length: 4, Data: 1

Set-SmbServerConfiguration -EnableSecuritySignature $true
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\enablesecuritysignature	Type: REG_DWORD, Length: 4, Data: 1

Set-SmbServerConfiguration -EncryptData $true
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\EncryptData	Type: REG_DWORD, Length: 4, Data: 1

Set-SmbServerConfiguration -EncryptionCiphers "AES_256_GCM, AES_256_CCM"
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\CipherSuiteOrder	Type: REG_MULTI_SZ, Length: 52, Data: AES_256_GCM, AES_256_CCM, 

Set-SmbServerConfiguration -RejectUnencryptedAccess $true
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\RejectUnencryptedAccess	Type: REG_DWORD, Length: 4, Data: 1
```
Encryption is enabled by default, some users reported slow read and write speeds. Disabling the encryption  (`$false`) may improve it, otherwise leave it enabled for your own security. Windows automatically uses the most advanced cipher, still 3.1.1 uses `128-GCM` by default. The last command prevent clients that do not support SMB encryption from connecting to encrypted shares.
> https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing
> https://techcommunity.microsoft.com/blog/filecab/configure-smb-signing-with-confidence/2418102

```ps
Set-SmbClientConfiguration -EnableMultiChannel $true
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\DisableMultiChannel	Type: REG_DWORD, Length: 4, Data: 0
```
Part of SMB3, is enabled by default. "Multichannel enables file servers to use multiple network connections simultaneously"
> https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn610980(v=ws.11)

⠀
Disabling leasing may help, but it disables core features like read/write/handle caching that negatively impact many applications, which rely on it.
```ps
Set-SmbServerConfiguration -EnableLeasing $false
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\DisableLeasing	Type: REG_DWORD, Length: 4, Data: 1
```
> https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/slow-smb-file-transfer#slow-open-of-office-documents

```ps
Set-SmbClientConfiguration -EnableSMBQUIC $true
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSMBQUIC	Type: REG_DWORD, Length: 4, Data: 1

Set-SmbServerConfiguration -EnableSMBQUIC $true
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\EnableSMBQUIC	Type: REG_DWORD, Length: 4, Data: 1
```
Uses QUIC instead of TCP - [SMB over QUIC prerequisites](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-over-quic?tabs=windows-admin-center%2Cpowershell2%2Cwindows-admin-center1#prerequisites)
> https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-over-quic?tabs=powershell%2Cpowershell2%2Cwindows-admin-center1

`None` - No min/max protocol version
`SMB202` - SMB 2.0.2
`SMB210` - SMB 2.1.0
`SMB300` - SMB 3.0.0
`SMB302` - SMB 3.0.2
`SMB311` - SMB 3.1.1

```ps
Set-SmbServerConfiguration -Smb2DialectMin SMB311 -Smb2DialectMax None
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\MaxSmb2Dialect	Type: REG_DWORD, Length: 4, Data: 65536
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\MinSmb2Dialect	Type: REG_DWORD, Length: 4, Data: 785

Set-SmbClientConfiguration -Smb2DialectMin SMB311 -Smb2DialectMax None
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\MaxSmb2Dialect	Type: REG_DWORD, Length: 4, Data: 65536
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\MinSmb2Dialect	Type: REG_DWORD, Length: 4, Data: 785
```
By default is it set to `None`, which means that the client can use any supported version. SMB 3.1.1, the most secure dialect of the protocol.
> https://learn.microsoft.com/en-us/windows-server/storage/file-server/manage-smb-dialects?tabs=powershell
> https://techcommunity.microsoft.com/blog/filecab/controlling-smb-dialects/860024

Disable default sharing:
```ps
Set-SmbServerConfiguration -AutoShareServer $false -AutoShareWorkstation $false -Force
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\AutoShareServer	Type: REG_DWORD, Length: 4, Data: 0
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\AutoShareWks	Type: REG_DWORD, Length: 4, Data: 0

# Get-SmbServerConfiguration | Select AutoShareServer, AutoShareWorkstation
```
> https://learn.microsoft.com/en-us/powershell/module/smbshare/set-smbserverconfiguration?view=windowsserver2025-ps  
> https://woshub.com/enable-remote-access-to-admin-shares-in-workgroup/

# QoS Policy

Adding the QoS policy via LGPE:
```ps
HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\Fortnite\Version    Type: REG_SZ, Length: 8, Data: 1.0
HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\Fortnite\Application Name    Type: REG_SZ, Length: 68, Data: FortniteClient-Win64-Shipping.exe
HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\Fortnite\Protocol    Type: REG_SZ, Length: 4, Data: * # TCP and UDP
HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\Fortnite\Local Port    Type: REG_SZ, Length: 4, Data: * # Any source port
HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\Fortnite\Local IP    Type: REG_SZ, Length: 4, Data: * # Any source IP
HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\Fortnite\Local IP Prefix Length    Type: REG_SZ, Length: 4, Data: *
HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\Fortnite\Remote Port    Type: REG_SZ, Length: 4, Data: * # Any destination port
HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\Fortnite\Remote IP    Type: REG_SZ, Length: 4, Data: * # Any destination IP
HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\Fortnite\Remote IP Prefix Length    Type: REG_SZ, Length: 4, Data: *
HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\Fortnite\DSCP Value    Type: REG_SZ, Length: 6, Data: 46 # High Priority, Expedited Forwarding (EF)
HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\Fortnite\Throttle Rate    Type: REG_SZ, Length: 6, Data: -1 # Unspecified throttle rate (none), 'Data' would specify rate in KBps
```
Capturing the network activity after adding the policy:
```ps
+ Versions: IPv4, Internet Protocol; Header Length = 20
- DifferentiatedServicesField: DSCP: 46, ECN: 0 # Works
   DSCP: (101110..) Differentiated services codepoint 46
   ECT:  (......0.) ECN-Capable Transport not set
   CE:   (.......0) ECN-CE not set
  TotalLength: 132 (0x84)
  Identification: 28587 (0x6FAB)
```
> https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/network-monitor-3  
> https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus1000/sw/4_0/qos/configuration/guide/nexus1000v_qos/qos_6dscp_val.pdf  
> https://github.com/valleyofdoom/PC-Tuning/blob/main/docs/research.md#2-how-can-you-verify-whether-a-dscp-qos-policy-is-working-permalink  
> https://webhostinggeeks.com/blog/what-is-differentiated-services-code-point-dscp/  
> https://learn.microsoft.com/en-us/windows-server/networking/technologies/qos/qos-policy-top  
> https://learn.microsoft.com/en-us/windows-server/networking/technologies/qos/qos-policy-manage

![](https://github.com/5Noxi/win-config/blob/main/network/images/qosvalues.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/network/images/qosexplanation.png?raw=true)

# Disable Network Discovery

"LLTDIO and Responder are network protocol drivers used for Link Layer Topology Discovery and network diagnostics. LLTDIO discovers network topology and supports QoS functions, while Responder allows the device to be identified and take part in network health assessments."
> https://gpsearch.azurewebsites.net/#1829
> https://gpsearch.azurewebsites.net/#1830

Disable network discovery (includes LLTDIO & Rspndr), by pasting the desired command into `powershell`:
```ps
Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled False -Profile Any​ # Domain​, Private, Public​
```
Get the current states with:
```ps
Get-NetFirewallRule -DisplayGroup "Network Discovery" | Select-Object Name, Enabled, Profile
```
> https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallrule?view=windowsserver2025-ps

```ps
svchost.exe	RegSetValue	HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\EnableLLTDIO	Type: REG_DWORD, Length: 4, Data: 0
svchost.exe	RegSetValue	HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowLLTDIOOnDomain	Type: REG_DWORD, Length: 4, Data: 0
svchost.exe	RegSetValue	HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowLLTDIOOnPublicNet	Type: REG_DWORD, Length: 4, Data: 0
svchost.exe	RegSetValue	HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\ProhibitLLTDIOOnPrivateNet	Type: REG_DWORD, Length: 4, Data: 0
svchost.exe	RegSetValue	HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\EnableRspndr	Type: REG_DWORD, Length: 4, Data: 0
svchost.exe	RegSetValue	HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowRspndrOnDomain	Type: REG_DWORD, Length: 4, Data: 0
svchost.exe	RegSetValue	HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\AllowRspndrOnPublicNet	Type: REG_DWORD, Length: 4, Data: 0
svchost.exe	RegSetValue	HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD\ProhibitRspndrOnPrivateNet	Type: REG_DWORD, Length: 4, Data: 0
```

Defaults on W11 LTSC IoT Enterprise:
```
Name                               Enabled        Profile
----                               -------        -------
NETDIS-UPnPHost-Out-TCP              False         Public
NETDIS-SSDPSrv-Out-UDP-Active         True        Private
NETDIS-WSDEVNT-Out-TCP-Active         True        Private
NETDIS-NB_Name-Out-UDP               False         Public
NETDIS-NB_Datagram-Out-UDP           False         Public
NETDIS-LLMNR-In-UDP                  False Domain, Public
NETDIS-DAS-In-UDP-Active              True        Private
NETDIS-SSDPSrv-In-UDP-Teredo          True         Public
NETDIS-UPnP-Out-TCP                  False Domain, Public
NETDIS-FDPHOST-In-UDP-Active          True        Private
NETDIS-WSDEVNT-In-TCP-Active          True        Private
NETDIS-UPnPHost-Out-TCP-Active        True        Private
NETDIS-WSDEVNTS-In-TCP-Active         True        Private
NETDIS-UPnPHost-In-TCP-Active         True        Private
NETDIS-NB_Name-In-UDP                False         Public
NETDIS-NB_Datagram-In-UDP-NoScope    False         Domain
NETDIS-FDRESPUB-WSD-In-UDP-Active     True        Private
NETDIS-WSDEVNTS-Out-TCP              False         Public
NETDIS-UPnPHost-Out-TCP-NoScope      False         Domain
NETDIS-WSDEVNT-In-TCP-NoScope        False         Domain
NETDIS-WSDEVNT-Out-TCP-NoScope       False         Domain
NETDIS-FDRESPUB-WSD-Out-UDP-Active    True        Private
NETDIS-LLMNR-Out-UDP                 False Domain, Public
NETDIS-WSDEVNTS-In-TCP-NoScope       False         Domain
NETDIS-SSDPSrv-In-UDP                False Domain, Public
NETDIS-DAS-In-UDP                    False Domain, Public
NETDIS-NB_Name-In-UDP-Active          True        Private
NETDIS-NB_Datagram-Out-UDP-Active     True        Private
NETDIS-NB_Datagram-In-UDP            False         Public
NETDIS-UPnPHost-In-TCP               False         Public
NETDIS-NB_Name-In-UDP-NoScope        False         Domain
NETDIS-WSDEVNTS-Out-TCP-NoScope      False         Domain
NETDIS-LLMNR-Out-UDP-Active           True        Private
NETDIS-UPnPHost-In-TCP-Teredo         True         Public
NETDIS-FDRESPUB-WSD-Out-UDP          False Domain, Public
NETDIS-SSDPSrv-In-UDP-Active          True        Private
NETDIS-LLMNR-In-UDP-Active            True        Private
NETDIS-WSDEVNT-Out-TCP               False         Public
NETDIS-WSDEVNTS-In-TCP               False         Public
NETDIS-NB_Datagram-In-UDP-Active      True        Private
NETDIS-SSDPSrv-Out-UDP               False Domain, Public
NETDIS-NB_Datagram-Out-UDP-NoScope   False         Domain
NETDIS-FDPHOST-Out-UDP               False Domain, Public
NETDIS-WSDEVNT-In-TCP                False         Public
NETDIS-UPnPHost-In-TCP-NoScope       False         Domain
NETDIS-WSDEVNTS-Out-TCP-Active        True        Private
NETDIS-FDRESPUB-WSD-In-UDP           False Domain, Public
NETDIS-FDPHOST-Out-UDP-Active         True        Private
NETDIS-FDPHOST-In-UDP                False Domain, Public
NETDIS-UPnP-Out-TCP-Active            True        Private
NETDIS-NB_Name-Out-UDP-Active         True        Private
NETDIS-NB_Name-Out-UDP-NoScope       False         Domain
```

# Congestion Provider

BBRv2 only works on W11 - can cause issues with applications (e.g. steelseries), can work fine. Fix:
```bat
netsh int ipv6 set gl loopbacklargemtu=disable
netsh int ipv4 set gl loopbacklargemtu=disable
```
Revert:
```bat
netsh int ipv6 set gl loopbacklargemtu=enable
netsh int ipv4 set gl loopbacklargemtu=enable
```
> https://dev.moe/en/3021

Info, which was used:
> https://www3.cs.stonybrook.edu/~anshul/comsnets24_bbrbbrv2.pdf  
> https://github.com/google/bbr  
> https://www.rfc-editor.org/rfc/rfc6582  
> https://internet2.edu/wp-content/uploads/2022/12/techex22-AdvancedNetworking-ExploringtheBBRv2CongestionControlAlgorithm-Tierney.pdf  
> https://datatracker.ietf.org/meeting/104/materials/slides-104-iccrg-an-update-on-bbr-00  
> https://www.speedguide.net/articles/tcp-congestion-control-algorithms-comparison-7423  
> https://datatracker.ietf.org/meeting/105/materials/slides-105-iccrg-bbr-v2-a-model-based-congestion-control-00

Get your current congestion provider, by pasting the following into powershell:
```
Get-NetTCPSetting | Select SettingName, CongestionProvider
```

![](https://github.com/5Noxi/win-config/blob/main/network/images/congnet.png?raw=true)
![](https://github.com/5Noxi/win-config/blob/main/network/images/congnet2.png?raw=true)

BBR2 (used):
```ps
netsh int ipv6 set gl loopbacklargemtu=disable
netsh int ipv4 set gl loopbacklargemtu=disable
netsh int tcp set supplemental Template=Internet CongestionProvider=bbr2
netsh int tcp set supplemental Template=Datacenter CongestionProvider=bbr2
netsh int tcp set supplemental Template=Compat CongestionProvider=bbr2
netsh int tcp set supplemental Template=DatacenterCustom CongestionProvider=bbr2
netsh int tcp set supplemental Template=InternetCustom CongestionProvider=bbr2
```
CTCP:
```ps
netsh int tcp set supplemental template=internet congestionprovider=CTCP
netsh int tcp set supplemental template=internetcustom congestionprovider=CTCP
netsh int tcp set supplemental Template=Compat CongestionProvider=CTCP
netsh int tcp set supplemental template=Datacenter congestionprovider=CTCP
netsh int tcp set supplemental template=Datacentercustom congestionprovider=CTCP
```
CUBIC:
```ps
netsh int tcp set supplemental template=internet congestionprovider=CUBIC
netsh int tcp set supplemental template=internetcustom congestionprovider=CUBIC
netsh int tcp set supplemental Template=Compat CongestionProvider=CUBIC
netsh int tcp set supplemental template=Datacenter congestionprovider=CUBIC
netsh int tcp set supplemental template=Datacentercustom congestionprovider=CUBIC
```
NewReno:
```ps
netsh int tcp set supplemental Template=Internet CongestionProvider=NewReno
netsh int tcp set supplemental Template=Datacenter CongestionProvider=NewReno
netsh int tcp set supplemental Template=Compat CongestionProvider=NewReno
netsh int tcp set supplemental Template=DatacenterCustom CongestionProvider=NewReno
netsh int tcp set supplemental Template=InternetCustom CongestionProvider=NewReno
```

# Disable WiFi

Self explaining.

# Disable Active Probing

Disables active internet probing (prevents windows from automatically checking if an internet connection is available). `MaxActiveProbes` (comment) is set to `1`, as `0` = unlimited (breaks connection status).

> https://github.com/5Noxi/wpr-reg-records/blob/main/records/NlaSvc.txt
> https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/troubleshoot-ncsi-guidance
> https://privacylearn.com/windows/disable-os-data-collection/disable-connectivity-checks/disable-active-connectivity-tests-breaks-internet-connection-status-captive-portals

Disable passive connectivity (NCSI) tests with:
```bat
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v PassivePollPeriod /t REG_DWORD /d 0 /f
::reg add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v PassivePollPeriod /t REG_DWORD /d 15 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v DisablePassivePolling /t REG_DWORD /d 1 /f
::reg delete"HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v DisablePassivePolling /f
```
```
Passive connectivity tests (NCSI) check internet status every 15 seconds by sending requests to Microsoft servers, which can expose network details, create privacy risks, and trigger unwanted connections. Disabling them stops this monitoring, reducing background network activity and potential VPN/firewall conflicts. However, it can cause Windows to falsely report no internet and break features that rely on NCSI for connectivity detection.
```
NCSI package name: `NcsiUwpApp` (breaks connection status icon)
> https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/internet-explorer-edge-open-connect-corporate-public-network

> [network/assets | probing-NcsiConfigData.c](https://github.com/5Noxi/win-config/blob/main/network/assets/probing-NcsiConfigData.c)

---

Miscellaneous notes:
```ps
reg add "HKLM\System\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v EnableUserActiveProbing /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v MaxActiveProbes /t REG_DWORD /d 1 /f

\Registry\Machine\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet : ActiveDnsProbeContent
\Registry\Machine\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet : ActiveDnsProbeContentV6
\Registry\Machine\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet : ActiveDnsProbeHost
\Registry\Machine\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet : ActiveDnsProbeHostV6
\Registry\Machine\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet : ActiveWebProbeContent
\Registry\Machine\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet : ActiveWebProbeContentV6
\Registry\Machine\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet : ActiveWebProbeHost
\Registry\Machine\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet : ActiveWebProbeHostV6
\Registry\Machine\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet : ActiveWebProbePath
\Registry\Machine\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet : ActiveWebProbePathV6
\Registry\Machine\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet : ReprobeThreshold
```

# Disable VPNs

SSTP VPN & other VPNs - enable the services, to revert it.

Get current VPN connections:
```ps
Get-VpnConnection
```
Remove a VPN connection with (or `Remove-VpnConnection`):
```bat
rasphone -r "Name"
```
or `WIN + I` > Network & Internet > VPN > Remove

> https://learn.microsoft.com/en-us/powershell/module/vpnclient/remove-vpnconnection?view=windowsserver2025-ps
> https://learn.microsoft.com/en-us/powershell/module/vpnclient/?view=windowsserver2025-ps

Disable `Allow VPN over metered networks` (`0` = On, `1` = Off):
```ps
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasMan\Parameters\Config\VpnCostedNetworkSettings" /v NoCostedNetwork /d 1 /f
```
```c
OSDATA__SYSTEM__CurrentControlSet__Services__RasMan__Parameters_1 = 
    L"SYSTEM\\CurrentControlSet\\Services\\RasMan\\Parameters\\Config\\VpnCostedNetworkSettings";

VpnRegQueryDWord(
    v13,
    OSDATA__SYSTEM__CurrentControlSet__Services__RasMan__Parameters_1,
    L"NoCostedNetwork",
    &g_donotUseCosted,
    v17);

if ( !v17[0] )
    g_donotUseCosted = 0; // default
```
Disable `Allow VPN while Roaming` (`0` = On, `1` = Off):
```ps
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasMan\Parameters\Config\VpnCostedNetworkSettings" /v NoRoamingNetwork /d 1 /f
```
```c
OSDATA__SYSTEM__CurrentControlSet__Services__RasMan__Parameters = 
    L"SYSTEM\\CurrentControlSet\\Services\\RasMan\\Parameters\\Config\\VpnCostedNetworkSettings";

VpnRegQueryDWord(
    v15,
    OSDATA__SYSTEM__CurrentControlSet__Services__RasMan__Parameters,
    L"NoRoamingNetwork",
    &g_donotUseRoaming,
    v17);

if ( !v17[0] )
    g_donotUseRoaming = 0; // default
```

> [network/assets | vpn-NlmGetCostedNetworkSettings.c](https://github.com/5Noxi/win-config/blob/main/network/assets/vpn-NlmGetCostedNetworkSettings.c)