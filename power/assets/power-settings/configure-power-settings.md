---
title: Configure power settings | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/configure-power-settings
description: This section contains information about the power settings that you can configure using the Windows provisioning framework. Each power setting topic includes the allowed values, meaning, and common usage scenarios for the setting.
---

# Configure power settings | Microsoft Learn

This section contains information about the power settings that you can configure using the Windows provisioning framework. Each power setting topic includes the allowed values, meaning, and common usage scenarios for the setting.

Tip

The primary audience for these topics is Original Equipment Manufacturers (OEMs). If you're a Windows device owner (consumer) and would like to learn more about power settings in Windows, please see [Shut down, sleep, or hibernate your PC](https://aka.ms/AAszj4j) on Microsoft's support site.

## Use Windows Configuration Designer to configure power settings

To configure the power settings, you will first create a provisioning package using [Windows Configuration Designer](/en-us/windows/configuration/provisioning-packages/provisioning-install-icd). You will then edit the customizations.xml file contained in the package to include your power settings. Use the XML file as one of the inputs to the Windows Configuration Designer command-line to generate either a provisioning package or a Windows image that contains the power settings. For information on how to use the Windows Configuration Designer CLI, see [Use the Windows Configuration Designer command-line interface](/en-us/windows/configuration/provisioning-packages/provisioning-command-line).

The power settings are not visible in the Windows Configuration Designer UI but appear under the main `Common\Power` namespace. This namespace is further divided into various groups including:

- `Policy\Settings` which includes the following subgroups:

    - `AdaptivePowerBehavior`
    - `Processor`
    - `Battery`
    - `Button`
    - `Display`
    - `Disk`
    - `EnergySaver`
    - `PCIExpress`
    - `Sleep`
    - `Misc`
- `Controls` which includes the following settings:

    - `LidNotificationsAreReliable`
    - `EnableInputSuppression`

The following example shows what your Windows provisioning answer file might look like after you've written it.

```XML
<?xml version="1.0" encoding="utf-8"?>
<WindowsCustomizatons>
  <PackageConfig xmlns="urn:schemas-Microsoft-com:Windows-ICD-Package-Config.v1.0">
    <ID>{<!-- ID needs to be the unique GUID for the package -->}</ID>
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
                <Sleep>
                  <SchemePersonality>
                    <Default SchemeAlias="Balanced">
                      <Setting>
                      <!-- Duration of time after sleep that the system automatically wakes and 
                           enters hibernate in seconds -->
                         <HibernateTimeout> 
                          <AcValue>1800</AcValue> <!-- 30 minutes -->
                          <DcValue>1800</DcValue> <!-- 30 minutes -->
                        </HibernateTimeout>
                      </Setting>
                    </Default>
                   </SchemePersonality>
                 </Sleep>
                 <Misc>
                   <SchemePersonality>
                     <Default SchemeAlias="Balanced">
                       <Setting>
                       <!-- Enables/Disables only WiFi connection during standby -->
                         <AllowWifiInStandby>
                           <AcValue>0</AcValue>
                           <DcValue>0</DcValue>
                         </AllowWifiInStandby>
                       </Setting>
                     </Default>
                   </SchemePersonality>
                  </Misc>
             </Settings>
           </Policy>
        </Power>
      </Common>
    </Customizations>
  </Settings>
</WindowsCustomizatons>
```

## Use Powercfg.exe to control power schemes

You can use the powercfg.exe tool to control power schemes by providing the GUID or alias for the setting. For more information on how to use this tool, see [Powercfg command-line options](/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options).