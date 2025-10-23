# Disable Automatic Map Downloads

Disables automatic network traffic on the settings page and prevents automatic downloading or updating of map data, limiting location-related data updates.

```c
v8 = 1; // Default
LOBYTE(a3) = 1;
v5 = 0;
MapsPersistedRegBoolean = RegUtils::GetMapsPersistedRegBoolean(this, L"AutoUpdateEnabled", a3, &v8);
if ( MapsPersistedRegBoolean >= 0 )
*a2 = v8 != 0;
else
return (unsigned int)ZTraceReportPropagation(
					   MapsPersistedRegBoolean,
					   "ServiceManager::GetAutoUpdateEnabledSetting",
					   3025,
					   this);
return v5;
```
```c
v8 = 1; // Default
LOBYTE(a3) = 1;
v5 = 0;
MapsPersistedRegBoolean = RegUtils::GetMapsPersistedRegBoolean(this, L"UpdateOnlyOnWifi", a3, &v8);
if ( MapsPersistedRegBoolean >= 0 )
*a2 = v8 != 0;
else
return (unsigned int)ZTraceReportPropagation(
					   MapsPersistedRegBoolean,
					   "ServiceManager::GetDownloadOnlyOnWifiSetting",
					   3043,
					   this);
return v5;
```
> https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-maps

`AutoDownloadAndUpdateMapData` & `AllowUntriggeredNetworkTrafficOnSettingsPage`:
> https://gpsearch.azurewebsites.net/#13439
> https://gpsearch.azurewebsites.net/#13350

```json
{"HKLM\\SYSTEM\\CurrentControlSet\\Services\\MapsBroker":{"Start":{"Type":"REG_DWORD","Data":4}},"HKLM\\SYSTEM\\Maps":{"AutoUpdateEnabled":{"Type":"REG_DWORD","Data":0},"UpdateOnlyOnWifi":{"Type":"REG_DWORD","Data":0}},"HKLM\\Software\\Policies\\Microsoft\\Windows\\Maps":{"AllowUntriggeredNetworkTrafficOnSettingsPage":{"Type":"REG_DWORD","Data":0},"AutoDownloadAndUpdateMapData":{"Type":"REG_DWORD","Data":0}}}
```
