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