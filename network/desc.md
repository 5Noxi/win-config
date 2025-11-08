# SMB Configuration

SMB Client -> Outbound connections:  
> https://learn.microsoft.com/en-us/powershell/module/smbshare/set-smbclientconfiguration?view=windowsserver2025-ps

SMB Server -> Inbound connections:  
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
```
> https://learn.microsoft.com/en-us/powershell/module/smbshare/set-smbserverconfiguration?view=windowsserver2025-ps  
> https://woshub.com/enable-remote-access-to-admin-shares-in-workgroup/

---

`Require NTLMv2 Session Security` (options applied for clients & servers):  
"This security setting allows a client to require the negotiation of 128-bit encryption and/or NTLMv2 session security. These values are dependent on the LAN Manager Authentication Level security setting value. The options are:

Require NTLMv2 session security: The connection will fail if NTLMv2 protocol is not negotiated.
Require 128-bit encryption: The connection will fail if strong encryption (128-bit) is not negotiated."

> https://en.wikipedia.org/wiki/NTLM#NTLMv2

```c
// NTLMv2 Off - 128 Bit Encryption On (default)
RegSetValue	HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec	Type: REG_DWORD, Length: 4, Data: 536870912

// NTLMv2 On - 128 Bit Encryption On
RegSetValue	HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec	Type: REG_DWORD, Length: 4, Data: 537395200

// NTLMv2 Off - 128 Bit Encryption Off
RegSetValue	HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec	Type: REG_DWORD, Length: 4, Data: 0
```

---

`Send unencrypted password to connect to third-party SMB servers`:  
```c
// Enabled (security risk)
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword	Type: REG_DWORD, Length: 4, Data: 1

// Disabled (default)
RegSetValue	HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword	Type: REG_DWORD, Length: 4, Data: 0
```

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

"The Link Layer Discovery Protocol (LLDP) is a vendor-neutral link layer protocol used by network devices for advertising their identity, capabilities, and neighbors on a local area network based on IEEE 802 technology, principally wired Ethernet. LLDP performs functions similar to several proprietary protocols, such as CDP, FDP, NDP and LLTD."

> https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol  
> https://gpsearch.azurewebsites.net/#1829  
> https://gpsearch.azurewebsites.net/#1830

Disable network discovery (includes LLTDIO, Rspndr, LLTD), by pasting the desired command into `powershell`:
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

```c
RegistryKey<unsigned char>::Initialize(
    this + 40,
    *(ADAPTER_CONTEXT**)this,
    *(((NDIS_HANDLE*)this) + 1),
    "DisableLLDP",
    0,
    1,
    0,  // default
    0,
    0
)
```
> > [network/assets | networkdisc-DataCenterBridgingConfiguration.c](https://github.com/5Noxi/win-config/blob/main/network/assets/networkdisc-DataCenterBridgingConfiguration.c)

---

```json
{
    "File":  "LinkLayerTopologyDiscovery.admx",
    "NameSpace":  "Microsoft.Policies.LinkLayerTopology",
    "Class":  "Machine",
    "CategoryName":  "LLTD_Category",
    "DisplayName":  "Turn on Mapper I/O (LLTDIO) driver",
    "ExplainText":  "This policy setting changes the operational behavior of the Mapper I/O network protocol driver.LLTDIO allows a computer to discover the topology of a network it\u0027s connected to. It also allows a computer to initiate Quality-of-Service requests such as bandwidth estimation and network health analysis.If you enable this policy setting, additional options are available to fine-tune your selection. You may choose the \"Allow operation while in domain\" option to allow LLTDIO to operate on a network interface that\u0027s connected to a managed network. On the other hand, if a network interface is connected to an unmanaged network, you may choose the \"Allow operation while in public network\" and \"Prohibit operation while in private network\" options instead.If you disable or do not configure this policy setting, the default behavior of LLTDIO will apply.",
    "Supported":  "WindowsVista",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows\\LLTD",
    "KeyName":  "EnableLLTDIO",
    "Elements":  [
                        {
                            "ValueName":  "AllowLLTDIOOnDomain",
                            "FalseValue":  "0",
                            "TrueValue":  "1",
                            "Type":  "Boolean"
                        },
                        {
                            "ValueName":  "AllowLLTDIOOnPublicNet",
                            "FalseValue":  "0",
                            "TrueValue":  "1",
                            "Type":  "Boolean"
                        },
                        {
                            "ValueName":  "ProhibitLLTDIOOnPrivateNet",
                            "FalseValue":  "0",
                            "TrueValue":  "1",
                            "Type":  "Boolean"
                        },
                        {
                            "Value":  "1",
                            "Type":  "EnabledValue"
                        },
                        {
                            "Value":  "0",
                            "Type":  "DisabledValue"
                        }
                    ]
},
{
    "File":  "LinkLayerTopologyDiscovery.admx",
    "NameSpace":  "Microsoft.Policies.LinkLayerTopology",
    "Class":  "Machine",
    "CategoryName":  "LLTD_Category",
    "DisplayName":  "Turn on Responder (RSPNDR) driver",
    "ExplainText":  "This policy setting changes the operational behavior of the Responder network protocol driver.The Responder allows a computer to participate in Link Layer Topology Discovery requests so that it can be discovered and located on the network. It also allows a computer to participate in Quality-of-Service activities such as bandwidth estimation and network health analysis.If you enable this policy setting, additional options are available to fine-tune your selection. You may choose the \"Allow operation while in domain\" option to allow the Responder to operate on a network interface that\u0027s connected to a managed network. On the other hand, if a network interface is connected to an unmanaged network, you may choose the \"Allow operation while in public network\" and \"Prohibit operation while in private network\" options instead.If you disable or do not configure this policy setting, the default behavior for the Responder will apply.",
    "Supported":  "WindowsVista",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows\\LLTD",
    "KeyName":  "EnableRspndr",
    "Elements":  [
                        {
                            "ValueName":  "AllowRspndrOnDomain",
                            "FalseValue":  "0",
                            "TrueValue":  "1",
                            "Type":  "Boolean"
                        },
                        {
                            "ValueName":  "AllowRspndrOnPublicNet",
                            "FalseValue":  "0",
                            "TrueValue":  "1",
                            "Type":  "Boolean"
                        },
                        {
                            "ValueName":  "ProhibitRspndrOnPrivateNet",
                            "FalseValue":  "0",
                            "TrueValue":  "1",
                            "Type":  "Boolean"
                        },
                        {
                            "Value":  "1",
                            "Type":  "EnabledValue"
                        },
                        {
                            "Value":  "0",
                            "Type":  "DisabledValue"
                        }
                    ]
},
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

# Disable Wi-Fi

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

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Connectivity\DisallowNetworkConnectivityActiveTests: value (DWord 1)
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

# Disable SMBv1/SMBv2

SMBv1 is only needed for old computers or software (that you usually don't have) and should be disabled, as it's unsafe & not efficient.

Detect current states with:
```ps
Get-SmbServerConfiguration | Select EnableSMB1Protocol, EnableSMB2Protocol
```
Disable it with (`$true` to enable it):
```ps
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```
, use the batch or turn off the feature off in `optionalfeatures` -> '**SMB 1.0/CIFS File Sharing Support**'

If you want to disable SMB2 & SMB3:
```ps
Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
```
`Set-SmbServerConfiguration $false`:
```ps
"Process Name","Operation","Path","Detail"
"wmiprvse.exe","RegSetValue","HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB2","Type: REG_DWORD, Length: 4, Data: 0"
"wmiprvse.exe","RegSetValue","HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1","Type: REG_DWORD, Length: 4, Data: 0"
```

| Functionality                                      | Disabled when SMBv3 is off       | Disabled when SMBv2 is off       |
|----------------------------------------------------|----------------------------------|----------------------------------|
| Transparent failover                               | Yes                              | No                               |
| Scale-out file server access                       | Yes                              | No                               |
| SMB Multichannel                                   | Yes                              | No                               |
| SMB Direct (RDMA)                                  | Yes                              | No                               |
| Encryption (end-to-end)                            | Yes                              | No                               |
| Directory leasing                                  | Yes                              | No                               |
| Performance optimization (small random I/O)        | Yes                              | No                               |
| Request compounding                                | No                               | Yes                              |
| Larger reads and writes                            | No                               | Yes                              |
| Caching of folder and file properties              | No                               | Yes                              |
| Durable handles                                    | No                               | Yes                              |
| Improved message signing (HMAC SHA-256)            | No                               | Yes                              |
| Improved scalability for file sharing              | No                               | Yes                              |
| Support for symbolic links                         | No                               | Yes                              |
| Client oplock leasing model                        | No                               | Yes                              |
| Large MTU / 10 GbE support                         | No                               | Yes                              |
| Improved energy efficiency (clients can sleep)     | No                               | Yes                              |

> https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3?tabs=client#disable-smbv2-or-smbv3-for-troubleshooting  
> https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3?tabs=server  
> https://techcommunity.microsoft.com/blog/filecab/stop-using-smb1/425858  
> https://thelinuxcode.com/how-to-detect-and-turn-on-off-smbv1-smbv2-and-smbv3-in-windows/

# Disable NetBIOS/mDNS/LLMNR

"`NetbiosOptions` specifies the configurable security settings for the NetBIOS service and determines the mode of operation for NetBIOS over TCP/IP on the parent interface."

Enabling the option includes disabling `LMHOSTS Lookups` - "LMHOSTS is a local text file Windows uses to map NetBIOS names to IPs when other NetBIOS methods (WINS, broadcast) don't give an answer. It lives in C:\Windows\System32\drivers\etc, there's an `lmhosts.sam` example, and it's checked only if `Enable LMHOSTS lookup` is on."

> https://en.wikipedia.org/wiki/LMHOSTS  
> https://github.com/5Noxi/wpr-reg-records/blob/main/records/NetBT.txt

`NetbiosOptions`:

| Value | Description                                                                                 |
| ----- | ------------------------------------------------------------------------------------------- |
| 0     | Specifies that the Dynamic Host Configuration Protocol (DHCP) setting is used if available. |
| 1     | Specifies that NetBIOS is enabled. This is the default value if DHCP is not available.      |
| 2     | Specifies that NetBIOS is disabled.                                                         |

Disabling `NetbiosOptions` via network center:
```ps
RegSetValue	HKLM\System\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{58f1d738-585f-40e2-aa37-39937f740875}\NetbiosOptions	Type: REG_DWORD, Length: 4, Data: 2
```

| Protocol                                     | Purpose                                                                   | How it works                                                                                                                      | Notes                                                                                   |
| -------------------------------------------- | ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| LLMNR (Link-Local Multicast Name Resolution) | Local name resolution when DNS isn't available                            | Sends multicast queries on the local link (IPv4 224.0.0.252, UDP 5355) asking "who has this name?", hosts that own the name reply | Windows-specific legacy fallback, vulnerable to spoofing/poisoning                      |
| mDNS (Multicast DNS)                         | Zero-config service/host discovery on local networks (e.g. printer.local) | Uses multicast to 224.0.0.251 (IPv6 ff02::fb) on UDP 5353, devices answer for their own .local names                              | Cross-platform (Apple Bonjour, now Windows), modern replacement for LLMNR in many cases |
| NetBIOS over TCP/IP                          | Legacy Windows naming, service announcement and sessions                  | Uses broadcasts or WINS to resolve NetBIOS names, historically used by SMB/Windows networking                                     | Very old, chatty, bigger attack surface, kept for backward compatibility                |

> https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution  
> https://en.wikipedia.org/wiki/Multicast_DNS  
> https://en.wikipedia.org/wiki/NetBIOS  

```json
{
    "File":  "DnsClient.admx",
    "NameSpace":  "Microsoft.Policies.DNSClient",
    "Class":  "Machine",
    "CategoryName":  "DNS_Client",
    "DisplayName":  "Configure multicast DNS (mDNS) protocol",
    "ExplainText":  "Specifies if the DNS client will perform name resolution over mDNS.If you enable this policy, the DNS client will use mDNS protocol.If you disable this policy setting, or if you do not configure this policy setting, the DNS client will use locally configured settings.",
    "Supported":  "Windows_10_0_RS2",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows NT\\DNSClient",
    "KeyName":  "EnableMDNS",
    "Elements":  [
                        {
                            "Value":  "1",
                            "Type":  "EnabledValue"
                        },
                        {
                            "Value":  "0",
                            "Type":  "DisabledValue"
                        }
                    ]
},
{
    "File":  "DnsClient.admx",
    "NameSpace":  "Microsoft.Policies.DNSClient",
    "Class":  "Machine",
    "CategoryName":  "DNS_Client",
    "DisplayName":  "Turn off smart multi-homed name resolution",
    "ExplainText":  "Specifies that a multi-homed DNS client should optimize name resolution across networks. The setting improves performance by issuing parallel DNS, link local multicast name resolution (LLMNR) and NetBIOS over TCP/IP (NetBT) queries across all networks. In the event that multiple positive responses are received, the network binding order is used to determine which response to accept.If you enable this policy setting, the DNS client will not perform any optimizations. DNS queries will be issued across all networks first. LLMNR queries will be issued if the DNS queries fail, followed by NetBT queries if LLMNR queries fail.If you disable this policy setting, or if you do not configure this policy setting, name resolution will be optimized when issuing DNS, LLMNR and NetBT queries.",
    "Supported":  "Windows8",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows NT\\DNSClient",
    "KeyName":  "DisableSmartNameResolution",
    "Elements":  [
                        {
                            "Value":  "1",
                            "Type":  "EnabledValue"
                        },
                        {
                            "Value":  "0",
                            "Type":  "DisabledValue"
                        }
                    ]
},
{
    "File":  "DnsClient.admx",
    "NameSpace":  "Microsoft.Policies.DNSClient",
    "Class":  "Machine",
    "CategoryName":  "DNS_Client",
    "DisplayName":  "NetBIOS learning mode",
    "ExplainText":  "Specifies if the DNS client will perform name resolution over NetBIOS.By default, the DNS client will disable NetBIOS name resolution on public networks for security reasons.To use this policy setting, click Enabled, and then select one of the following options from the drop-down list:Disable NetBIOS name resolution: Never allow NetBIOS name resolution.Allow NetBIOS name resolution: Always allow NetBIOS name resolution.Disable NetBIOS name resolution on public networks: Only allow NetBIOS name resolution on network adapters which are not connected to public networks.NetBIOS learning mode: Always allow NetBIOS name resolution and use it as a fallback after mDNS/LLMNR queries fail.If you disable this policy setting, or if you do not configure this policy setting, the DNS client will use locally configured settings.",
    "Supported":  "WindowsVista",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows NT",
    "KeyName":  "DNSClient",
    "Elements":  [
                        {
                            "Type":  "Enum",
                            "ValueName":  "EnableNetbios",
                            "Items":  [
                                        {
                                            "DisplayName":  "Disable NetBIOS name resolution",
                                            "Value":  "0"
                                        },
                                        {
                                            "DisplayName":  "Allow NetBIOS name resolution",
                                            "Value":  "1"
                                        },
                                        {
                                            "DisplayName":  "Disable NetBIOS name resolution on public networks",
                                            "Value":  "2"
                                        },
                                        {
                                            "DisplayName":  "NetBIOS learning mode",
                                            "Value":  "3"
                                        }
                                    ]
                        }
                    ]
},
{
    "File":  "DnsClient.admx",
    "NameSpace":  "Microsoft.Policies.DNSClient",
    "Class":  "Machine",
    "CategoryName":  "DNS_Client",
    "DisplayName":  "Turn off multicast name resolution",
    "ExplainText":  "Specifies that link local multicast name resolution (LLMNR) is disabled on the DNS client.LLMNR is a secondary name resolution protocol. With LLMNR, queries are sent using multicast over a local network link on a single subnet from a DNS client to another DNS client on the same subnet that also has LLMNR enabled. LLMNR does not require a DNS server or DNS client configuration, and provides name resolution in scenarios in which conventional DNS name resolution is not possible.If you enable this policy setting, LLMNR will be disabled on all available network adapters on the DNS client.If you disable this policy setting, or you do not configure this policy setting, LLMNR will be enabled on all available network adapters.",
    "Supported":  "WindowsVista",
    "KeyPath":  "Software\\Policies\\Microsoft\\Windows NT\\DNSClient",
    "KeyName":  "EnableMulticast",
    "Elements":  [
                        {
                            "Value":  "0",
                            "Type":  "EnabledValue"
                        },
                        {
                            "Value":  "1",
                            "Type":  "DisabledValue"
                        }
                    ]
},
```

# Disable IPv6

`0xFFFFFFFF` disables all IPv6 interfaces, even ones Windows needs. The TCP/IP stack then waits for them to initialize and times out, which adds the `~5s` boot delay. The documentation below was taken from the official support articles.

Min Value: `0x00` (default value)  
Max Value: `0xFF` (IPv6 disabled)
Recommended by Microsoft: `0x20` (Prefer IPv4 over IPv6)

|IPv6 Functionality|Registry value and comments|
|---|---|
|Prefer IPv4 over IPv6|Decimal 32<br/>Hexadecimal 0x20<br/>Binary xx1x xxxx<br/><br/>Recommended instead of disabling IPv6.<br/><br/>To confirm preference of IPv4 over IPv6, perform the following commands:<br/><br/>- Open the command prompt or PowerShell.<br/>- Use the 'ping' command to check the preferred IP version. For example, "ping bing.com". <br/>- If IPv4 is preferred, you should see an IPv4 address being returned in the response.<br/><br/>Network Connections:<br/><br/>- Open the command prompt or PowerShell.<br/>- Use 'netsh interface ipv6 show prefixpolicies<br/>- Check if the 'Prefix' policies have been modified to prioritize IPv4.<br/>- The '::ffff:0:0/96' prefix should have a higher precedence than the '::/0' prefix.<br/><br/>For Example, if you have two entries, one with precedence 35 and another with precedence 40, the one with precedence 40 will be preferred.|
|Disable IPv6|Decimal 255<br/>Hexadecimal 0xFF<br/>Binary 1111 1111<br/><br/>See [startup delay occurs after you disable IPv6 in Windows](https://support.microsoft.com/help/3014406) if you encounter startup delay after disabling IPv6 in Windows 7 SP1 or Windows Server 2008 R2 SP1. <br/><br/> Additionally, system startup will be delayed for five seconds if IPv6 is disabled by incorrectly, setting the **DisabledComponents** registry setting to a value of 0xffffffff. The correct value should be 0xff. For more information, see [Internet Protocol Version 6 (IPv6) Overview](/previous-versions/windows/it-pro/windows-8.1-and-8/hh831730(v=ws.11)). <br/><br/>  The **DisabledComponents** registry value doesn't affect the state of the check box. Even if the **DisabledComponents** registry key is set to disable IPv6, the check box in the Networking tab for each interface can be checked. This is an expected behavior.<br/><br/> You cannot completely disable IPv6 as IPv6 is used internally on the system for many TCPIP tasks. For example, you will still be able to run ping `::1` after configuring this setting.|
|Disable IPv6 on all nontunnel interfaces|Decimal 16<br/>Hexadecimal 0x10<br/>Binary xxx1 xxxx|
|Disable IPv6 on all tunnel interfaces|Decimal 1<br/>Hexadecimal 0x01<br/>Binary xxxx xxx1|
|Disable IPv6 on all nontunnel interfaces (except the loopback) and on IPv6 tunnel interface|Decimal 17<br/>Hexadecimal 0x11<br/>Binary xxx1 xxx1|
|Prefer IPv6 over IPv4|Binary xx0x xxxx|
|Re-enable IPv6 on all nontunnel interfaces|Binary xxx0 xxxx|
|Re-enable IPv6 on all tunnel interfaces|Binary xxx xxx0|
|Re-enable IPv6 on nontunnel interfaces and on IPv6 tunnel interfaces|Binary xxx0 xxx0|

## How to calculate the registry value

Windows use bitmasks to check the `DisabledComponents` values and determine whether a component should be disabled.

|Name|Setting|
|---|---|
|Tunnel|Disable tunnel interfaces|
|Tunnel6to4|Disable 6to4 interfaces|
|TunnelIsatap|Disable Isatap interfaces|
|Tunnel Teredo|Disable Teredo interfaces|
|Native|Disable native interfaces (also PPP)|
|PreferIpv4|Prefer IPv4 in default prefix policy|
|TunnelCp|Disable CP interfaces|
|TunnelIpTls|Disable IP-TLS interfaces|
  
For each bit, **0** means false and **1** means true. Refer to the following table for an example.

|Setting|Prefer IPv4 over IPv6 in prefix policies|Disable IPv6 on all nontunnel interfaces|Disable IPv6 on all tunnel interfaces|Disable IPv6 on nontunnel interfaces (except the loopback) and on IPv6 tunnel interface|
|---|---|---|---|---|
|Disable tunnel interfaces|0|0|1|1|
|Disable 6to4 interfaces|0|0|0|0|
|Disable Isatap interfaces|0|0|0|0|
|Disable Teredo interfaces|0|0|0|0|
|Disable native interfaces (also PPP)|0|1|0|1|
|Prefer IPv4 in default prefix policy.|1|0|0|0|
|Disable CP interfaces|0|0|0|0|
|Disable IP-TLS interfaces|0|0|0|0|
|Binary|0010 0000|0001 0000|0000 0001|0001 0001|
|Hexadecimal|0x20|0x10|0x01|0x11|

> https://github.com/MicrosoftDocs/SupportArticles-docs/blob/main/support/windows-server/networking/configure-ipv6-in-windows.md  
> https://support.microsoft.com/en-us/topic/startup-delay-occurs-after-you-disable-ipv6-in-windows-da7e0f60-27b0-c27e-7709-7ee9abfc6ef1

# Disable Wi-Fi Sense

Wi-Fi Sense is enabled by default and, when you're signed in with a Microsoft account, can share Wi-Fi access (password stays encrypted in MS servers) with your Outlook and Skype contacts, Facebook contacts can be added. When you join a new network, it asks whether to share it. Networks you used before the upgrade won't trigger the prompt.

> https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/configure-wifi-sense-and-paid-wifi-service

```json
{
    "File":  "wlansvc.admx",
    "NameSpace":  "Microsoft.Policies.WlanSvc",
    "Class":  "Machine",
    "CategoryName":  "WlanSettings_Category",
    "DisplayName":  "Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services",
    "ExplainText":  "This policy setting determines whether users can enable the following WLAN settings: \"Connect to suggested open hotspots,\" \"Connect to networks shared by my contacts,\" and \"Enable paid services\".\"Connect to suggested open hotspots\" enables Windows to automatically connect users to open hotspots it knows about by crowdsourcing networks that other people using Windows have connected to.\"Connect to networks shared by my contacts\" enables Windows to automatically connect to networks that the user\u0027s contacts have shared with them, and enables users on this device to share networks with their contacts.\"Enable paid services\" enables Windows to temporarily connect to open hotspots to determine if paid services are available.If this policy setting is disabled, both \"Connect to suggested open hotspots,\" \"Connect to networks shared by my contacts,\" and \"Enable paid services\" will be turned off and users on this device will be prevented from enabling them.If this policy setting is not configured or is enabled, users can choose to enable or disable either \"Connect to suggested open hotspots\" or \"Connect to networks shared by my contacts\".",
    "Supported":  "Windows_10_0_NOSERVER",
    "KeyPath":  "Software\\Microsoft\\wcmsvc\\wifinetworkmanager\\config",
    "KeyName":  "AutoConnectAllowedOEM",
    "Elements":  [
                        {
                            "Value":  "1",
                            "Type":  "EnabledValue"
                        },
                        {
                            "Value":  "0",
                            "Type":  "DisabledValue"
                        }
                    ]
},
```

# Enable Offloads

Network offload features transfer processing tasks from the CPU to the network adapter hardware, reducing system overhead and improving overall network performance. Common offload features include TCP checksum offload, Large Send Offload (LSO), and Receive Side Scaling (RSS).

Enabling network adapter offload features is usually beneficial. However, the network adapter might not be powerful enough to handle the offload capabilities with high throughput. For example, consider a network adapter with limited hardware resources. In that case, enabling segmentation offload features might reduce the maximum sustainable throughput of the adapter. However, if the reduced throughput is acceptable, you should enable the segmentation offload features.

"*IPChecksumOffloadIPv4" = 3
"*LsoV1IPv4" = 1
"*LsoV2IPv4" = 1
"*LsoV2IPv6" = 1
"*TCPChecksumOffloadIPv4" = 3
"*TCPChecksumOffloadIPv6" = 3
"*UDPChecksumOffloadIPv4" = 3
"*UDPChecksumOffloadIPv6" = 3
"*TCPConnectionOffloadIPv4" = 1
"*TCPConnectionOffloadIPv6" = 1
"*TCPUDPChecksumOffloadIPv4" = 3
"*TCPUDPChecksumOffloadIPv6" = 3
"*PMARPOffload" = 0
"*PMNSOffload" = 0
"*IPsecOffloadV1IPv4" = 3
"*IPsecOffloadV2" = 3
"*IPsecOffloadV2IPv4" = 3
"*QoSOffload" = 1
#"*PMWiFiRekeyOffload" = 1
"*UsoIPv4" = 1
"*UsoIPv6" = 1

Excludes:
"SaOffloadCapacityEnabled" = 0 # deprecated (Chimney too)

Enable static offloads. For example, enable the UDP Checksums, TCP Checksums, and Send Large Offload (LSO) settings.

> https://learn.microsoft.com/en-us/windows-server/networking/technologies/network-subsystem/net-sub-performance-top
> https://www.intel.com/content/www/us/en/support/articles/000005593/ethernet-products.html

# Disable Wake On

"*WakeOnMagicPacket" = 0
"*WakeOnPattern" = 0
"S5WakeOnLan" = 0
"WakeOnLink" = 0
"WakeOnMagicPacketFromS5" = 0
"ForceWakeFromMagicPacketOnModernStandby" = 0
"EnableWakeOnManagmentOnTCO" = 0
"WakeFromS5" = 0
"WakeOn" = 0
"WakeOnFastStartup" = 0
"WakeOnLinkChange" = 0

---

Miscellaneous notes:
```inf
HKR, Ndi\Params\WakeUpModeCap,       ParamDesc,   0 , %WakeUpMode%
HKR, Ndi\Params\WakeUpModeCap,       default,  0  , "2"
HKR, Ndi\Params\WakeUpModeCap,       type,      0  , "enum"
HKR, Ndi\Params\WakeUpModeCap\enum,  "0",        0 , %WakeUpMode_None%
HKR, Ndi\Params\WakeUpModeCap\enum,  "1",        0 , %WakeUpMode_Magic%
HKR, Ndi\Params\WakeUpModeCap\enum,  "2",        0 , %WakeUpMode_Pattern%
```
```c
"WakeUpModeCap": { "Type": "REG_SZ", "Data": 0 },
```

# Increase Buffers

The maximum data differs for users, e.g. if applying `4096` it may get rejected, see `inf` blocks below.

Transmit Buffers:  
> Defines the number of Transmit Descriptors. Transmit Descriptors are data segments that enable the adapter to track transmit packets in the system memory. Depending on the size of the packet, each transmit packet requires one or more Transmit Descriptors. You might choose to increase the number of Transmit Descriptors if you notice a problem with transmit performance. Increasing the number of Transmit Descriptors can enhance transmit performance. But, Transmit Descriptors consume system memory. If transmit performance is not an issue, use the default setting.

Receive Buffers:  
> Sets the number of buffers used by the driver when copying data to the protocol memory. Increasing this value can enhance the receive performance, but also consumes system memory. Receive Descriptors are data segments that enable the adapter to allocate received packets to memory. Each received packet requires one Receive Descriptor, and each descriptor uses 2 KB of memory.

> https://edc.intel.com/content/www/us/en/design/products/ethernet/adapters-and-devices-user-guide/29.3.1/receive-buffers/  
> https://edc.intel.com/content/www/us/en/design/products/ethernet/adapters-and-devices-user-guide/transmit-buffers/

```inf
; *TransmitBuffers
HKR, Ndi\params\*TransmitBuffers,               ParamDesc,              0, %TransmitBuffers%
HKR, Ndi\params\*TransmitBuffers,               default,                0, "512"
HKR, Ndi\params\*TransmitBuffers,               min,                    0, "80"
HKR, Ndi\params\*TransmitBuffers,               max,                    0, "2048"
HKR, Ndi\params\*TransmitBuffers,               step,                   0, "8"
HKR, Ndi\params\*TransmitBuffers,               Base,                   0, "10"
HKR, Ndi\params\*TransmitBuffers,               type,                   0, "int"

; *ReceiveBuffers
HKR, Ndi\params\*ReceiveBuffers,                ParamDesc,              0, %ReceiveBuffers%
HKR, Ndi\params\*ReceiveBuffers,                default,                0, "256"
HKR, Ndi\params\*ReceiveBuffers,                min,                    0, "80"
HKR, Ndi\params\*ReceiveBuffers,                max,                    0, "2048"
HKR, Ndi\params\*ReceiveBuffers,                step,                   0, "8"
HKR, Ndi\params\*ReceiveBuffers,                Base,                   0, "10"
HKR, Ndi\params\*ReceiveBuffers,                type,                   0, "int"

HKR, NDI\Params\*ReceiveBuffers,  ParamDesc, 0, "%RecvRingSize%"
HKR, NDI\Params\*ReceiveBuffers,  default,    0, "512"
HKR, NDI\Params\*ReceiveBuffers,  min, 	   0, "64"
HKR, NDI\Params\*ReceiveBuffers,  max, 	   0, "4096"
HKR, NDI\Params\*ReceiveBuffers,  step,	   0, "1"
HKR, NDI\Params\*ReceiveBuffers,  Base,	   0, "10"
HKR, NDI\Params\*ReceiveBuffers,  type,	   0, "dword"
HKR, "", *ReceiveBuffers, 0, "512"

HKR, NDI\Params\*TransmitBuffers,  ParamDesc, 0, "%SendRingSize%"
HKR, NDI\Params\*TransmitBuffers,  default,	  0, "2048"
HKR, NDI\Params\*TransmitBuffers,  min,	   0, "256"
HKR, NDI\Params\*TransmitBuffers,  max,	   0, "4096"
HKR, NDI\Params\*TransmitBuffers,  step,    0, "1"
HKR, NDI\Params\*TransmitBuffers,  Base,    0, "10"
HKR, NDI\Params\*TransmitBuffers,  type,    0, "dword"
HKR, "", *TransmitBuffers,  %REG_SZ%, "2048"
```

Reminder: Each adapter uses it's own default values, means that the `default`/`min`/`max` may be different for you.

# Enable IM/ITR

Some NICs expose multiple interrupt-moderation levels. Use interrupt moderation for CPU-bound workloads and weigh host-CPU savings against added latency. For the lowest possible latency, disable Interrupt Moderation, accepting higher CPU use as a tradeoff. At higher link speeds more interrupts drive up CPU and hurt performance, increasing the ITR lowers the interrupt rate and improves performance. IM batches received packets and starts a timer on first arrival, interrupting when the buffer fills or the timer expires. Many NICs offer more than on/off, with low/medium/high rates that map to shorter or longer timers to favor latency or reduce interrupts.

> https://edc.intel.com/content/www/us/en/design/products/ethernet/adapters-and-devices-user-guide/interrupt-moderation-rate/  
> https://learn.microsoft.com/en-us/windows-server/networking/technologies/network-subsystem/net-sub-performance-tuning-nics?tabs=powershell#interrupt-moderation  
> https://enterprise-support.nvidia.com/s/article/understanding-interrupt-moderation

```
Off: ITR = 0 (no limit)
Minimal: ITR = 200
Low: ITR = 400
Medium: ITR = 950
High: ITR = 2000
Extreme: ITR = 3600
Adaptive: ITR = 65535
```
ITR = Interrupt Throttle Rate.

```inf
;  Interrupt Throttle Rate
HKR, Ndi\Params\ITR,                                    ParamDesc,              0, %InterruptThrottleRate%
HKR, Ndi\Params\ITR,                                    default,                0, "65535"
HKR, Ndi\Params\ITR\Enum,                               "65535",                0, %Adaptive%
HKR, Ndi\Params\ITR\Enum,                               "3600",                 0, %Extreme%
HKR, Ndi\Params\ITR\Enum,                               "2000",                 0, %High%
HKR, Ndi\Params\ITR\Enum,                               "950",                  0, %Medium%
HKR, Ndi\Params\ITR\Enum,                               "400",                  0, %Low%
HKR, Ndi\Params\ITR\Enum,                               "200",                  0, %Minimal%
HKR, Ndi\Params\ITR\Enum,                               "0",                    0, %Off%
HKR, Ndi\Params\ITR,                                    type,                   0, "enum"

; *InterruptModeration
HKR, Ndi\Params\*InterruptModeration,                   ParamDesc,              0, %InterruptModeration%
HKR, Ndi\Params\*InterruptModeration,                   default,                0, "1"
HKR, Ndi\Params\*InterruptModeration\Enum,              "0",                    0, %Disabled%
HKR, Ndi\Params\*InterruptModeration\Enum,              "1",                    0, %Enabled%
HKR, Ndi\Params\*InterruptModeration,                   type,                   0, "enum"
```

```
\Registry\Machine\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\00XX : ITR
\Registry\Machine\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\00XX : *InterruptModeration
```

# Enable RSS

"*NumRssQueues" = 2
"*NumaNodeId"= 0
"*RSS"= 1
"*RSSProfile"= 4
"*RssBaseProcGroup"= 0
#"*RssBaseProcNumber"= 2
"*RssMaxProcGroup"= 0
#"*RssMaxProcNumber" = 2
#"RssV2" = 1

> https://learn.microsoft.com/en-us/windows-hardware/drivers/network/introduction-to-receive-side-scaling  
> https://learn.microsoft.com/en-us/windows-hardware/drivers/network/non-rss-receive-processing  
> https://learn.microsoft.com/en-us/windows-hardware/drivers/network/rss-with-message-signaled-interrupts

# Disable File/Printer Sharing

Disables "Allow other on the network to access shared files and printers on this device" via `@FirewallAPI.dll,-28502` & `ms_msclient`.

```ps
PS C:\Users\Nohuxi> Get-NetFirewallRule | sort -unique Group | sort DisplayGroup | ft DisplayGroup, Group

DisplayGroup                                                                      Group
------------                                                                      -----
File and Printer Sharing                                                          @FirewallAPI.dll,-28502
File and Printer Sharing (Restrictive)                                            @FirewallAPI.dll,-28672

PS C:\Users\Nohuxi> Get-NetAdapterBinding -Name *

Name                           DisplayName                                        ComponentID          Enabled
----                           -----------                                        -----------          -------
Ethernet                       File and Printer Sharing for Microsoft Networks    ms_server            False
```

> https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/networking-mpssvc-svc-firewallgroups-firewallgroup-group  
> https://learn.microsoft.com/en-us/powershell/module/netadapter/get-netadapterbinding?view=windowsserver2025-ps

```json
{
	"File":  "WindowsSandbox.admx",
	"NameSpace":  "Microsoft.Policies.WindowsSandbox",
	"Class":  "Machine",
	"CategoryName":  "WindowsSandbox",
	"DisplayName":  "Allow printer sharing with Windows Sandbox",
	"ExplainText":  "This policy setting enables or disables printer sharing from the host into the Sandbox.If you enable this policy setting, host printers will be shared into Windows Sandbox. If you disable this policy setting, Windows Sandbox will not be able to view printers from the host.If you do not configure this policy setting, printer redirection will be disabled.",
	"Supported":  "Windows_11_0_NOSERVER_ENTERPRISE_EDUCATION_PRO_SANDBOX",
	"KeyPath":  "SOFTWARE\\Policies\\Microsoft\\Windows\\Sandbox",
	"KeyName":  "AllowPrinterRedirection",
	"Elements":  [
						{
							"Value":  "1",
							"Type":  "EnabledValue"
						},
						{
							"Value":  "0",
							"Type":  "DisabledValue"
						}
					]
},
```

# Disable LLSE

This setting is used to enable/disable the logging of link state changes. If enabled, a link-up change event or a link-down change event generates a message that is displayed in the system event logger. This message contains the link’s speed and duplex. Administrators view the event message from the system event log.

The following events are logged:  
- The link is up. (`LINK_UP_CHANGE`)
- The link is down. (`LINK_DOWN_CHANGE`)
- Mismatch in duplex. (`LINK_DUPLEX_MISMATCH`)
- Spanning Tree Protocol detected.

```inf
;Log Link State Event
HKR,Ndi\Params\LogLinkStateEvent,                       ParamDesc,              0, %LogLinkState%
HKR,Ndi\Params\LogLinkStateEvent,                       Type,                   0, "enum"
HKR,Ndi\Params\LogLinkStateEvent,                       Default,                0, "51"
HKR,Ndi\Params\LogLinkStateEvent\Enum,                  "51",                   0, %Enabled%
HKR,Ndi\Params\LogLinkStateEvent\Enum,                  "16",                   0, %Disabled%
```

---

Miscellaenous notes:
```c
"LogWolEvent" = 16  // ?
```

# Disable Flow Control

A sending station (computer or network switch) may be transmitting data faster than the other end of the link can accept it. Using flow control, the receiving station can signal the sender requesting suspension of transmissions until the receiver catches up.

- For adapters to benefit from this feature, link partners must support flow control frames.  
- On systems running a Microsoft Windows Server* operating system, enabling QoS/priority flow control will disable link level flow control.  
- Some devices support Auto Negotiation. Selecting this will cause the device to advertise the value stored in its NVM (usually "Disabled").

> https://edc.intel.com/content/www/us/en/design/products/ethernet/adapters-and-devices-user-guide/flow-control/

# Enable Jumbo Packets

As the name says ("Jumbo"), it is used for big packets, you won't use this feature. Jumbo packets are disabled by default. Enable Jumbo Packets **only if all devices across the network support them** and are configured to use the same frame size.

The Jumbo Frames feature enables or disables Jumbo Packet capability. The standard Ethernet frame size is about `1514 bytes`, while Jumbo Packets are larger than this. Jumbo Packets can increase throughput and decrease CPU utilization. However, additional latency may be introduced.

- Enable Jumbo frames only if devices across the network support them and are configured to use the same frame size. When setting up Jumbo Frames on other network devices, be aware that different network devices calculate Jumbo Frame sizes differently. Some devices include the header information in the frame size while others do not. Intel® adapters do not include header information in the frame size.
- Supported protocols are limited to IP (TCP, UDP).
- Using Jumbo frames at 10 or 100 Mbps can result in poor performance or loss of link.
- You must not lower Receive_Buffers or Transmit_Buffers below 256 if jumbo frames are enabled. Doing so will cause loss of link.
- When configuring Jumbo frames on a switch, set the frame size 4 bytes higher for CRC, plus 4 bytes if using VLANs or QoS packet tagging.

> https://www.intel.com/content/www/us/en/support/articles/000005593/ethernet-products.html  
> https://edc.intel.com/content/www/us/en/design/products/ethernet/adapters-and-devices-user-guide/30.5/jumbo-frames/

```inf
HKR, Ndi\params\*JumboPacket,	ParamDesc,	0, %JumboPacket%
HKR, Ndi\params\*JumboPacket,	Type,		0, "enum"
HKR, Ndi\params\*JumboPacket\enum,	"0",	0, "%Bytes1514%"
HKR, Ndi\params\*JumboPacket\enum,	"1",	0, "%Bytes4088%"
HKR, Ndi\params\*JumboPacket\enum,	"2",	0, "%Bytes9014%"
HKR, Ndi\params\*JumboPacket,	Default,	0, "0"
```
`1514` = Disabled.

# Disable VMQ

VMQ is a scaling networking technology for the Hyper-V switch. Without VMQ the networking performance of the Hyper-V switch bound to this network adapter may be reduced. VMQ offloads packet processing to NIC hardware queues, with each queue tied to a specific VM. This increases throughput, spreads work across CPU cores, lowers host CPU use, and scales effectively as more VMs are added on Hyper-V.

VMQ is enabled by default:
```inf
HKR,Ndi\Params\*VMQ,ParamDesc, ,%VMQ%
HKR,Ndi\Params\*VMQ,type,      ,enum
HKR,Ndi\Params\*VMQ,default,   ,1
HKR,Ndi\Params\*VMQ\enum,0,    ,%Disabled%
HKR,Ndi\Params\*VMQ\enum,1,    ,%Enabled%
```

| Value | Description | Allowed Values | Default | Notes |
| ----  | ---- | ---- | ---- | ---- |
| `*VMQ`| Enable/disable the VMQ feature. | `0` Disabled - `1` Enabled | `1` | Enumeration keyword. |
| `*VMQLookaheadSplit` | Enable/disable splitting RX buffers into lookahead and post-lookahead buffers. | `0` Disabled - `1` Enabled | `1` | Starting with NDIS 6.30 / Windows Server 2012, this keyword is no longer supported. |
| `*VMQVlanFiltering` | Enable/disable filtering packets by VLAN ID in the MAC header. | `0` Disabled - `1` Enabled | `1` | Enumeration keyword. |
| `*RssOrVmqPreference` | Define whether VMQ capabilities should be enabled instead of RSS. | `0` Report RSS capabilities - `1` Report VMQ capabilities | `0`     | - |
| `*TenGigVmqEnabled` | Enable/disable VMQ on all 10 Gbps adapters. | `0` System default (disabled for Windows Server 2008 R2) - `1` Enabled - `2` Explicitly disabled | - | Miniport that supports VMQ must not read this subkey. |
| `*BelowTenGigVmqEnabled` | Enable/disable VMQ on all adapters <10 Gbps. | `0` System default (disabled for Windows Server 2008 R2) - `1` Enabled - `2` Explicitly disabled | - | Miniport that supports VMQ must not read this subkey. |

> https://github.com/5Noxi/windows-driver-docs/blob/staging/windows-driver-docs-pr/network/standardized-inf-keywords-for-vmq.md  
> https://docs.nvidia.com/networking/display/winofv55053000/ethernet+registry+keys#src-25134589_EthernetRegistryKeys-FlowControlOptions  
> https://github.com/5Noxi/windows-driver-docs/blob/staging/windows-driver-docs-pr/network/virtual-machine-queue-architecture.md  
> https://github.com/5Noxi/windows-driver-docs/blob/staging/windows-driver-docs-pr/network/introduction-to-ndis-virtual-machine-queue--vmq-.md

# Enable RSC/URO

When receiving data, the miniport driver, NDIS, and TCP/IP must all look at each protocol data unit (PDU) header information separately. When large amounts of data are being received, a large amount of overhead is created. Receive segment coalescing (RSC) reduces this overhead by coalescing a sequence of received segments and passing them to the host TCP/IP stack in one operation, so that NDIS and TCP/IP need to only look at one header for the entire sequence.

Starting in Windows 11, version 24H2, UDP receive segment coalescing offload (URO) enables network interface cards (NICs) to coalesce UDP receive segments. NICs can combine UDP datagrams from the same flow that match a set of rules into a logically contiguous buffer. These combined datagrams are then indicated to the Windows networking stack as a single large packet.

Coalescing UDP datagrams reduces the CPU cost to process packets in high-bandwidth flows, resulting in higher throughput and fewer cycles per byte.

> https://learn.microsoft.com/en-us/windows-hardware/drivers/network/udp-rsc-offload  
> https://learn.microsoft.com/en-us/windows-hardware/drivers/network/overview-of-receive-segment-coalescing

```c
void __fastcall ReceiveSideCoalescing::ReadRegistryParameters(struct ADAPTER_CONTEXT **this)
{
  RegistryKey<unsigned char>::Initialize(
    (enum RegKeyState *)((char *)this + 36),
    this[1],
    *((NDIS_HANDLE *)this[1] + 383),
    (PUCHAR)"*RSCIPv4",
    0,      // default
    1u,     // range 0-1
    0,
    0,
    0);

  RegistryKey<unsigned char>::Initialize(
    (enum RegKeyState *)((char *)this + 44),
    this[1],
    *((NDIS_HANDLE *)this[1] + 383),
    (PUCHAR)"*RSCIPv6",
    0,      // default
    1u,     // range 0-1
    0,
    0,
    0);

  RegistryKey<unsigned char>::Initialize(
    (enum RegKeyState *)(this + 2),
    this[1],
    *((NDIS_HANDLE *)this[1] + 383),
    (PUCHAR)"ForceRscEnabled",
    0,      // default
    1u,     // range 0-1
    0,
    0,
    0);

  RegistryKey<enum HdSplitLocation>::Initialize(
    (enum RegKeyState *)(this + 3),
    this[1],
    *((NDIS_HANDLE *)this[1] + 383),
    (PUCHAR)"RscMode",
    0,      // default
    2u,     // range 0-2
    1u,     // step
    0,
    0);
}
```

---

Miscellaneous notes:
```c
"ForceRscEnabled": { "Type": "REG_SZ", "Data": 1 },
"RscMode": { "Type": "REG_SZ", "Data": 1 },
```