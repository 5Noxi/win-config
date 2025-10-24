# Explorer Options

It changes every setting, which is shown in the `Folder Options` window. Some are personal preference.

Enable compact mode:
```bat
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v UseCompactMode /t REG_DWORD /d 1
```
Set it to `0` to get the default mode back.

Show hidden & protected files/folders:
```bat
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f
```
Set `Hidden` to `2` and `ShowSuperHidden` to `0` to disable it.

```json
{
  "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer": {
    "ShowFrequent": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "ShowRecent": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "ShowCloudFilesInQuickAccess": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "ShowDriveLettersFirst": {
      "Type": "REG_DWORD",
      "Data": 0
    }
  },
  "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced": {
    "IconsOnly": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "UseCompactMode": {
      "Type": "REG_DWORD",
      "Data": 1
    },
    "ShowTypeOverlay": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "FolderContentsInfoTip": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "Hidden": {
      "Type": "REG_DWORD",
      "Data": 2
    },
    "HideDrivesWithNoMedia": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "HideFileExt": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "HideMergeConflicts": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "ShowSuperHidden": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "SeparateProcess": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "PersistBrowsers": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "ShowEncryptCompressedColor": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "ShowInfoTip": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "ShowPreviewHandlers": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "ShowStatusBar": {
      "Type": "REG_DWORD",
      "Data": 1
    },
    "ShowSyncProviderNotifications": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "AutoCheckSelect": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "SharingWizardOn": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "TypeAhead": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "NavPaneExpandToCurrentFolder": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "NavPaneShowAllCloudStates": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "NavPaneShowAllFolders": {
      "Type": "REG_DWORD",
      "Data": 0
    },
    "TaskbarDa": {
      "Type": "REG_DWORD",
      "Data": 0
    }
  }
}
```