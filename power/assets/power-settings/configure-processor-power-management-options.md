---
title: Processor power management options | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/configure-processor-power-management-options
description: The Windows 10 processor power management (PPM) algorithms implement OS-level functionality that allows the OS to efficiently use the available processing resources on a platform by balancing the user's expectations of performance and energy efficiency.
---

# Processor power management options | Microsoft Learn

The Windows 10 processor power management (PPM) algorithms implement OS-level functionality that allows the OS to efficiently use the available processing resources on a platform by balancing the user's expectations of performance and energy efficiency.

The algorithms have the following characteristics:

- They scale from big servers to tablet form factors.
- They are customizable through a statically configurable power policy infrastructure.
- They are hierarchical and abstracted in a manner that separates platform-agnostic portions of the algorithms from platform-specific portions.

At a high-level, the Windows PPM is made up of the following parts:

- **Core parking engine** - Makes global scalability decisions about the workload and determines the optimum set of compute cores to execute with.
- **Performance state engine** - Makes per-processor performance scaling decisions.
- **Platform specific controls** - Implements the mechanics of state transitions and optionally provides feedback about the effectiveness of OS state decisions and runtime platform constraints.

IHV partners can enable preliminary validation and measurement of the effects of the policy controls on different hardware configurations.

## Power profiles

You can use the Windows Provisioning framework to configure the processor power settings described in this section. First, create a provisioning package using [Windows Configuration Designer](https://learn.microsoft.com/en-us/windows/configuration/provisioning-packages/provisioning-install-icd). You will then edit the customizations.xml file contained in the package to include your power settings, which appear under the `Common\Power\Policy\Settings\Processor` namespace. Use the XML file as one of the inputs to the Windows Configuration Designer command-line interface to generate either a provisioning package that contains the power settings. You can then apply the provisioning package to the image. For information on how to use the Windows Configuration Designer CLI, see [Use the Windows Configuration Designer command-line interface](https://learn.microsoft.com/en-us/windows/configuration/provisioning-packages/provisioning-command-line).

The processor namespace is divided into sets of identical power processor configurations called power profiles. The power profiles are used by the power processor engine to adapt the performance and parking algorithm on various system use cases.

Windows 10 supports the following profiles:

- *Default* profile is the configuration set that is active most of the time. These settings are indentical to those for the balanced power scheme. This provides for an alternative method to configure the balanced power scheme settings via the windows provisioning framework.
- *LowLatency* is the profile that is activated during boot and during app launch time.
- *LowPower* is the profile that is activated during the buffering phase of media playback scenarios. This profile is not applicable if Media [Quality of Service](https://learn.microsoft.com/en-us/windows/win32/procthread/quality-of-service) is configured.
- *GameMode* profile is enabled when the 'Game Mode' setting toggle is turned on and the user is playing a game. You can use this profile to finetune processor settings for your devices with Game Mode.
- *Mixed Reality* is the profile that is activated when a Windows Mixed Reality headset is connected to the system and the user is interacting with a MR application.
- *Constrained* is a profile activated by the battery saver feature on Windows 10 for desktop editions (Home, Pro, Enterprise, and Education). This is not available on Windows 10 Mobile.
- *ScreenOff* is a profile used on [Modern Standby](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/modern-standby) systems. It is engaged when is screen is turned off -- no remote desktop connections and there are no system & execution required power requests outstanding, no mobile hotspot is engaged. It is disengaged when the system enters the sleep or display turn back on. Please refer to diagram in the section [Summary of key points](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/modern-standby-states). This profile corresponds to Presence to DAM phase in that diagram.
- *Standby* is a profile used on [Modern Standby](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/modern-standby) systems. It is engaged when the system enters its long term sleep phase -- all system quiescing behavior has completed. It is disengaged when the system awakes from the sleep. Please refer to diagram in the section [Summary of key points](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/modern-standby-states). This profile corresponds to Low power phase to Resiliency phase in that diagram.

Each profile supports the following configuration settings:

- [CPMinCores](options-for-core-parking-cpmincores.md)
- [CPMaxCores](options-for-core-parking-cpmaxcores.md)
- [CPIncreaseTime](options-for-core-parking-cpincreasetime.md)
- [CPDecreaseTime](options-for-core-parking-cpdecreasetime.md)
- [CPConcurrency](options-for-core-parking-cpconcurrency.md)
- [CPDistribution](options-for-core-parking-cpdistribution.md)
- [CPHeadroom](options-for-core-parking-cpheadroom.md)
- [CpLatencyHintUnpark](options-for-core-parking-cplatencyhintunpark.md)
- [IdleDemoteThreshold](options-for-perf-state-engine-idledemotethreshold.md)
- [IdlePromoteThreshold](options-for-perf-state-engine-idlepromotethreshold.md)
- [MaxPerformance](options-for-perf-state-engine-maxperformance.md)
- [MinPerformance](options-for-perf-state-engine-minperformance.md)
- [PerfIncreasePolicy](options-for-perf-state-engine-perfincreasepolicy.md)
- [PerfIncreaseThreshold](options-for-perf-state-engine-perfincreasethreshold.md)
- [PerfIncreaseTime](options-for-perf-state-engine-perfincreasetime.md)
- [PerfDecreasePolicy](options-for-perf-state-engine-perfdecreasepolicy.md)
- [PerfDecreaseThreshold](options-for-perf-state-engine-perfdecreasethreshold.md)
- [PerfDecreaseTime](options-for-perf-state-engine-perfdecreasetime.md)
- [PerfLatencyHint](options-for-perf-state-engine-perflatencyhint.md)
- [LatencyHintEpp](options-for-perf-state-engine-latencyhintepp.md)
- [PerfAutonomousMode](options-for-perf-state-engine-perfautonomousmode.md)
- [PerfEnergyPreference](options-for-perf-state-engine-perfenergypreference.md)
- [ModuleUnparkPolicy](options-for-perf-state-engine-moduleunparkpolicy.md)
- [ComplexUnparkPolicy](options-for-perf-state-engine-complexunparkpolicy.md)
- [SmtUnparkPolicy](options-for-perf-state-engine-smtunparkpolicy.md)

On systems with processors with heterogeneous architecture, the configuration settings for efficiency class 1 cores use a similar naming convention.

The common parameters have the suffix "1" to indicate efficiency class. Hetero-specific parameters have the prefix "Hetero".

- [CPMinCores1](options-for-core-parking-cpmincores.md)
- [CPMaxCores1](options-for-core-parking-cpmaxcores.md)
- [HeteroIncreaseTime](configuration-for-hetero-power-scheduling-heteroincreasetime.md)
- [HeteroDecreaseTime](configuration-for-hetero-power-scheduling-heterodecreasetime.md)
- [HeteroIncreaseThreshold](configuration-for-hetero-power-scheduling-heteroincreasethreshold.md)
- [HeteroDecreaseThreshold](configuration-for-hetero-power-scheduling-heterodecreasethreshold.md)
- [CpLatencyHintUnpark1](options-for-core-parking-cplatencyhintunpark.md)
- [MaxPerformance1](options-for-perf-state-engine-maxperformance.md)
- [MinPerformance1](options-for-perf-state-engine-minperformance.md)
- [PerfIncreasePolicy1](options-for-perf-state-engine-perfincreasepolicy.md)
- [PerfIncreaseThreshold1](options-for-perf-state-engine-perfincreasethreshold.md)
- [PerfIncreaseTime1](options-for-perf-state-engine-perfincreasetime.md)
- [PerfDecreasePolicy1](options-for-perf-state-engine-perfdecreasepolicy.md)
- [PerfDecreaseThreshold1](options-for-perf-state-engine-perfdecreasethreshold.md)
- [PerfDecreaseTime1](options-for-perf-state-engine-perfdecreasetime.md)
- [PerfLatencyHint1](options-for-perf-state-engine-perflatencyhint.md)
- [LatencyHintEpp1](options-for-perf-state-engine-latencyhintepp.md)
- [HeteroClass1InitialPerf](configuration-for-hetero-power-scheduling-heteroclass1initialperf.md)
- [HeteroClass0FloorPerf](configuration-for-hetero-power-scheduling-heteroclass0floorperf.md)
- [HeteroIncreaseThreshold1](configuration-for-hetero-power-scheduling-heteroincreasethreshold1.md)
- [HeteroDecreaseThreshold1](configuration-for-hetero-power-scheduling-heterodecreasethreshold1.md)

**Game Mode Profile**

The game mode power profile is available as an OEM opt-in feature for laptops starting with the Windows 10 May 2019 Update (19H1) and you'll have to deploy it via provisioning packages during image creation. See below for an example of a customization xml file that defines processor power management settings for the Game Mode Power Profile and refer to the 'Game Mode Test Instructions' document for further guidance on customization options and deployment. This example sets the minimum processor performance state to 100% thereby biasing the CPU towards performance. For more tuning guidance, please reach out to your silicon vendor.

```xml
<?xml version="1.0" encoding="utf-8"?>
<WindowsCustomizatons>  
  <PackageConfig xmlns="urn:schemas-Microsoft-com:Windows-ICD-Package-Config.v1.0">  
    <ID>b8aca924-e386-436e-a50e-bdec4d1715a1</ID>  <!-- ID needs to be be unique GUID for the package -->  
    <Name>CustomOEM.Power.Settings.Control</Name>  
    <Version>1.0</Version>  
    <OwnerType>OEM</OwnerType>  
  </PackageConfig>  
  <Settings xmlns="urn:schemas-microsoft-com:windows-provisioning">  
    <Customizations>  
      <Common>  
          <Power> 
            <Policy> 
              <Settings> 
                <Processor> 
                  <SchemePersonality> 
                    <Profile SchemeAlias="Balanced"> 
                      <Setting ProfileAlias="GameMode"> 
                        <MinPerformance> 
                          <AcValue>100</AcValue> 
                          <DcValue>100</DcValue> 
                        </MinPerformance> 
                      </Setting> 
                    </Profile> 
                  </SchemePersonality> 
                </Processor> 
              </Settings> 
            </Policy> 
          </Power>  
      </Common>  
    </Customizations>  
  </Settings>  
</WindowsCustomizatons> 
```

**Power Profiles and their Provisioning ProfileAlias**

Using the customization XML as an example, you can create a provisioning package for all power profiles by matching the `<Setting ProfileAlias="?">` xml tag to their provisioning aliases. See below for list of power profiles and their corresponding aliases.

Note

PPM profiles are tuned by Silicon vendors to optimize power and performance of processors. Please reach out to your silicon vendor for tuning guidance before modifying processor power management settings.

| Profile Name | Profile Alias |
| --- | --- |
| Default | "Default" |
| Low Latency | "LowLatency" |
| Low Power | "LowPower" |
| Constrained | "Constrained" |
| Screen Off | "ScreenOff" |
| Standby | "Standby" |
| Game Mode | "GameMode" |
| Mixed Reality | "SustainedPerf" |

## Quality of Service

Power profiles provide system wide configuration of processor power management, impacting all running workloads equally. In contrast, the Quality of Service (QoS) feature provides differentiated performance and power for workloads with different QoS levels. For example, this enables tuning foreground HighQoS activity to prioritize performance, while tuning other QoS levels to prioritize power efficiency. For more information, see [Quality of Service](https://learn.microsoft.com/en-us/windows/win32/procthread/quality-of-service).

Each QoS level supports the following configuration settings:

- [MaxFrequency](options-for-perf-state-engine-maxfrequency.md)
- [MaxPerformance](options-for-perf-state-engine-maxperformance.md)
- [MinPerformance](options-for-perf-state-engine-minperformance.md)
- [PerfAutonomousMode](options-for-perf-state-engine-perfautonomousmode.md)
- [PerfAutonomousWindow](options-for-perf-state-engine-perfautonomouswindow.md)
- [PerfBoostMode](options-for-perf-state-engine-perfboostmode.md)
- [PerfEnergyPreference](options-for-perf-state-engine-perfenergypreference.md)
- [PerfLatencyHint](options-for-perf-state-engine-perflatencyhint.md)
- [LatencyHintEpp](options-for-perf-state-engine-latencyhintepp.md)
- [SchedulingPolicy](configuration-for-hetero-power-scheduling-schedulingpolicy.md)
- [ShortSchedulingPolicy](configuration-for-hetero-power-scheduling-shortschedulingpolicy.md)
- [LongThreadArchClassLowerThreshold](configuration-for-hetero-power-scheduling-longthreadarchclasslowerthreshold.md)
- [LongThreadArchClassUpperThreshold](configuration-for-hetero-power-scheduling-longthreadarchclassupperthreshold.md)
- [ShortThreadArchClassLowerThreshold](configuration-for-hetero-power-scheduling-shortthreadarchclasslowerthreshold.md)
- [ShortThreadArchClassUpperThreshold](configuration-for-hetero-power-scheduling-shortthreadarchclassupperthreshold.md)

On systems with processors with heterogeneous architecture, the configuration settings for efficiency class 1 cores use a similar naming convention.

The common parameters have the suffix "1" to indicate efficiency class.

- [MaxFrequency1](options-for-perf-state-engine-maxfrequency.md)
- [MaxPerformance1](options-for-perf-state-engine-maxperformance.md)
- [MinPerformance1](options-for-perf-state-engine-minperformance.md)
- [PerfEnergyPreference1](options-for-perf-state-engine-perfenergypreference.md)
- [PerfLatencyHint1](options-for-perf-state-engine-perflatencyhint.md)
- [LatencyHintEpp1](options-for-perf-state-engine-latencyhintepp.md)

**Quality of Service Levels and their Provisioning ProfileAlias**

Using the customization XML as an example, you can create a provisioning package for all QoS levels by matching the `<Setting ProfileAlias="?">` xml tag to their provisioning aliases. See below for list of QoS levels and their corresponding aliases.

Note

QoS levels are tuned by Silicon vendors to optimize power and performance of processors. Please reach out to your silicon vendor for tuning guidance before modifying processor power management settings. For details about various QoS levels refer [Quality of Service](https://learn.microsoft.com/en-us/windows/win32/procthread/quality-of-service)

| Quality of Service Level | Profile Alias |
| --- | --- |
| High | "Default" |
| Medium | "EntryLevelPerf" |
| Low | "Background" |
| Utility | "Utility" |
| Eco | "Eco" |
| Media | "Multimedia" |
| Deadline | Uses only [PerfLatencyHint](options-for-perf-state-engine-perflatencyhint.md) and [LatencyHintEpp](options-for-perf-state-engine-latencyhintepp.md) from "Multimedia" profile |
