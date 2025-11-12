# Noverse Windows Configuration

Information gathered via binary string extraction, WPR, IDA, Procmon, etc. Default values from WinDbg, IDA, and stock installations. Some options lack proof, as they're easily traceable. Minor mistakes or misinterpretations may exist, corrections are welcome.

The tool is based on the GitHub repository and parses its information out of it. The [`App Tools`](https://github.com/5Noxi/app-tools)/[`Game Tools`](https://github.com/5Noxi/game-tools) are external PowerShell scripts, same goes for the [`Component Manager`](https://github.com/5Noxi/comp-mgr), [`Blocklist Manager`](https://github.com/5Noxi/blocklist-mgr) & [`Bitmask Calculator`](https://github.com/5Noxi/bitmask-calc).

## My Projects

You can find all of my other projects here:
> https://5noxi.github.io/projects.html  
> https://github.com/5Noxi

More miscellaneous uploads:
> https://discord.gg/E2ybG4j9jU

## Issues

Report any kind of issues either in the repository or on the Discord server:
> https://github.com/5Noxi/win-config/issues  
> https://discord.com/channels/836870260715028511/1372991172015820900

## Requirements

> https://www.python.org/downloads/windows

```ps
pip install PySide6 mistune requests
```

# Contribution

`Option Name` (`json` examples) must be the same as the `.md` title.

### Overview
| Context | Allowed actions |
| ------ | ------ |
| `COMMANDS`                           | `run_powershell`, `delete_path`, `create_path`, `scheduled_task`, `tcp_congestion`, `netbind`, `optional_feature`, `restart_explorer`, `bcdedit`, `registry_pattern`, `mmagent`, `nvidia_key`, `ethernet_key` |
| Registry hives (`HKCU\`, `HKLM\`...) | Direct value set, `deletevalue` |

### Actions & Requirements
| Action | Required / optional arguments |
| ------ | ------ |
| `run_powershell`   | Required: `Command` - Optional: `Elevated` |
| `delete_path`      | Required: `Paths` (array or string) - Optional: `Recurse` (use %ENV%, not $env:ENV here) |
| `create_path`      | Use one: `Path` or `Paths` (array) - Optional: `File` / `IsFile` (bool) to create a file instead of directories |
| `scheduled_task`   | Use one: `TaskName` or `TaskNames` (array) - Required: `TaskAction` (`run`, `stop`, `enable`, `disable`, `delete`) |
| `tcp_congestion`   | Required: `Templates` (string or array), `Provider` (or `Value`) |
| `netbind`          | Required: `Components` (array or string) - Required: `State` (`enable` \| `disable`) |
| `optional_feature` | Required: `Features` (array or string) - Required: `State` (`enable` \| `disable`) - Optional: `Arguments` (array or string), `Elevated` |
| `restart_explorer` | (no arguments) |
| `bcdedit`          | Required: `Name` (or `Option`) - One of: `Value` or `Delete`/`Remove` (bool) |
| `registry_pattern` | Required: `Pattern`, `Operations` (array) - Optional: `ExcludeSubPaths`, `ExcludePatterns`, `ExcludeSegments`, `Exclude`, `Root`, `Message` |
| `mmagent`          | Required: `Setting` (or `Option`/`Name`), desired state via one of `Enabled`/`Enable`/`State` (bool) - Optional: `Elevated` |
| `nvidia_key`       | Required: `Values` -> map of valueName -> `{ Type, Data }` (or `{ Action: "deletevalue" }`) - Optional: `SubPath`/`SubKey` for relative subkey, `Refresh` to rescan adapter |
| `ethernet_key`     | Required: `Values` -> map of valueName -> `{ Type, Data }` (or `{ Action: "deletevalue" }`) - Optional: `SubPath`/`SubKey`, `Refresh` to rescan adapter, `NetIdPath` template containing the literal `{NetID}` placeholder to target other hives |

### Buttons
| Key | Purpose |
| ------ | ------ |
| `__control` | `{ "type": "button", "label": "name }` |


### Examples
```json
{
  "Option Name - Direct Writes (single key/values)": {
    "apply": {
      "HKCU\\Software\\Noverse": {
        "Enabled": { "Type": "REG_DWORD", "Data": 1 },
        "Profile": { "Type": "REG_SZ", "Data": "stable" },
        "Blob": { "Type": "REG_BINARY", "Data": [222, 173, 190, 239] }
      }
    },
    "revert": {
      "HKCU\\Software\\Noverse": {
        "Enabled": { "Action": "deletevalue" },
        "Profile": { "Action": "deletevalue" },
        "Blob": { "Action": "deletevalue" }
      }
    }
  },
  "Option Name - Default Value + Create/Delete Key": {
    "apply": {
      "HKCU\\Software\\Noverse": {
        "": { "Type": "REG_SZ", "Data": "DefaultDisplayName" },
        "Version": { "Type": "REG_SZ", "Data": "1.0.0" }
      },
      "COMMANDS": {
        "EnsureCacheFolder": {
          "Action": "create_path",
          "Paths": "%PROGRAMDATA%\\Noverse\\Cache"
        }
      }
    },
    "revert": {
      "HKCU\\Software\\Noverse": {
        "Action": "delete_path",
        "Paths": "HKCU\\Software\\Noverse",
        "Recurse": true
      }
    }
  },
  "Option Name - Only update if value exists": {
    "apply": {
      "HKCU\\Software\\Noverse": {
        "ExistingSwitch": { "Type": "REG_DWORD", "Data": 0, "OnlyExisting": true }
      }
    },
    "revert": {
      "HKCU\\Software\\Noverse": {
        "ExistingSwitch": { "Action": "deletevalue" }
      }
    }
  },
  "Option Name - Edits across any path containing 'Noverse' (wildcards)": {
    "apply": {
      "COMMANDS": {
        "TuneAllNoverseProfiles": { // Define any name
          "Action": "registry_pattern",
          "Pattern": "HKCU\\Software\\**Noverse**\\**\\Profiles\\*",
          "Operations": [
            { "SubPath": "Settings1", "Name": "Enabled", "Type": "REG_DWORD", "Value": 1 },
            { "SubPath": "Settings2", "Name": "Channel", "Type": "REG_SZ", "Value": "Test" }
          ]
        }
      }
    },
    "revert": {
      "COMMANDS": {
        "UntuneAllNoverseProfiles": {
          "Action": "registry_pattern",
          "Pattern": "HKCU\\Software\\**Noverse**\\**\\Profiles\\*",
          "Operations": [
            { "SubPath": "Settings1", "Name": "Enabled", "Operation": "deletevalue" },
            { "SubPath": "Settings2", "Name": "Channel", "Operation": "deletevalue" }
          ]
        }
      }
    }
  },
  "Option Name - Target a service/device style subtree with exclusions": {
    "apply": {
      "COMMANDS": {
        "SetNoverseAdvanced": {
          "Action": "registry_pattern",
          "Pattern": "HKLM\\SYSTEM\\*ControlSet*\\Services\\**Noverse**\\**",
          "ExcludeSubPaths": ["KeyName"],
          "Operations": [
            { "Name": "Throttle", "Type": "REG_DWORD", "Value": 0 },
            { "SubPath": "Parameters", "Name": "TraceLevel", "Operation": "deletevalue" }
          ]
        }
      }
    },
    "revert": {
      "COMMANDS": {
        "RevertNoverseAdvanced": {
          "Action": "registry_pattern",
          "Pattern": "HKLM\\SYSTEM\\*ControlSet*\\Services\\**Noverse**\\**",
          "Operations": [
            { "Name": "Throttle", "Operation": "deletevalue" }
          ]
        }
      }
    }
  },
  "Option Name - PowerShell Command": {
    "apply": {
      "COMMANDS": {
        "WriteViaPS": {
          "Action": "run_powershell",
          "Elevated": true, // if set the command will get executed with MinSudo
          "Command": "New-Item -Path 'HKCU:\\Software\\Noverse' -Force | Out-Null; New-Item -Path 'HKCU:\\Software\\Noverse' -Force | Out-Null; New-ItemProperty -Path 'HKCU:\\Software\\Noverse' -Name 'Computed' -PropertyType String -Value ([string](Get-Date -Format o)) -Force | Out-Null"
        }
      }
    },
    "revert": {
      "HKCU\\Software\\Noverse": {
        "Computed": { "Action": "deletevalue" }
      }
    }
  },
  "Option Name - Button (no revert)": {
    "__control": { "type": "button", "label": "Open" },
    "COMMANDS": {
      "RemoveWindowsOld": {
        "Action": "run_powershell",
        "Command": "Start-Process powershell -ArgumentList '-NoProfile -Command \"iwr -UseBasicParsing -Uri https://raw.githubusercontent.com/5Noxi/win-config/refs/heads/main/visibility/assets/Icon-Spacing.ps1 | iex\"'"
      }
    }
  },
  "Option Name - Delete Paths (multi)": {
    "__control": { "type": "button", "label": "Delete" },
    "COMMANDS": {
      "DeleteNoversePaths": {
        "Action": "delete_path",
        "Recurse": true,
        "Paths": [
          "HKCU\\Software\\Noverse\\Nohuxi",
          "%PROGRAMDATA%\\Noverse\\Cache", // don't use $env:
          "%LOCALAPPDATA%\\Noverse\\Temp"
        ]
      }
    }
  },
  "Option Name - Scheduled Tasks": {
    "apply": {
      "COMMANDS": {
        "DisableNoverseTasks": {
          "Action": "scheduled_task",
          "TaskNames": [
            "\\Noverse\\Telemetry*",
            "\\Microsoft\\Windows\\Noverse\\Update"
          ],
          "TaskAction": "disable"
        }
      }
    },
    "revert": {
      "COMMANDS": {
        "EnableNoverseTasks": {
          "Action": "scheduled_task",
          "TaskNames": [
            "\\Noverse\\Telemetry*",
            "\\Microsoft\\Windows\\Noverse\\Update"
          ],
          "TaskAction": "enable"
        }
      }
    }
  },
  "Option Name - Scheduled Tasks (run/stop/delete)": {
    "apply": {
      "COMMANDS": {
        "RunOnce": { 
          "Action": "scheduled_task", 
          "TaskName": "\\Noverse\\Telemetry Daily", 
          "TaskAction": "run" 
        },
        "StopNow": { 
          "Action": "scheduled_task", 
          "TaskName": "\\Noverse\\Telemetry Daily", 
          "TaskAction": "stop" 
        }
      }
    },
    "revert": {
      "COMMANDS": {
        "DeleteTask": { 
          "Action": "scheduled_task", 
          "TaskName": "\\Noverse\\Telemetry Daily", 
          "TaskAction": "delete" 
        }
      }
    }
  },
  "Option Name - TCP Congestion": {
    "apply": {
      "COMMANDS": {
        "SetTCPProvider_BBR2": {
          "Action": "tcp_congestion",
          "Templates": [
            "Internet",
            "InternetCustom",
            "Compat",
            "Datacenter",
            "DatacenterCustom"
          ],
          "Provider": "bbr2"
        }
      }
    },
    "revert": {
      "COMMANDS": {
        "SetTCPProvider_CUBIC": {
          "Action": "tcp_congestion",
          "Templates": [
            "Internet",
            "InternetCustom",
            "Compat",
            "Datacenter",
            "DatacenterCustom"
          ],
          "Provider": "cubic"
        }
      }
    }
  },
  "Option Name - Netbind": {
    "apply": {
      "COMMANDS": {
        "DisableBindings": {
          "Action": "netbind",
          "Components": ["ms_tcpip6", "ms_lltdio"],
          "State": "disable"
        }
      }
    },
    "revert": {
      "COMMANDS": {
        "EnableBindings": {
          "Action": "netbind",
          "Components": ["ms_tcpip6", "ms_lltdio"],
          "State": "enable"
        }
      }
    }
  },
  "Option Name - Optional Features": {
    "apply": {
      "COMMANDS": {
        "DisableOptionalFeatures": {
          "Action": "optional_feature",
          "Arguments": [ "/NoRestart", "/Quiet" ],
          "Features": [
            "TelnetClient",
            "SMB1Protocol"
          ],
          "State": "disable"
        }
      }
    },
    "revert": {
      "COMMANDS": {
        "EnableOptionalFeatures": {
          "Action": "optional_feature",
          "Features": [
            "TelnetClient",
            "SMB1Protocol"
          ],
          "State": "enable"
        }
      }
    }
  },
  "Option Name - Restart Explorer": {
    "apply": {
      "HKCU\\Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\\InprocServer32": {
        "": { "Type": "REG_SZ", "Data": "" } 
      },
      "COMMANDS": { "RestartExplorer": { "Action": "restart_explorer" } }
    },
    "revert": {
      "HKCU\\Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}": { 
        "Action": "delete_path", "Recurse": true
      },
      "COMMANDS": { "RestartExplorer": { "Action": "restart_explorer" } }
    }
  },
  "Option Name - BCDEdits": {
    "apply": {
      "COMMANDS": {
        "HypervisorOff": {
          "Action": "bcdedit",
          "Name": "hypervisorlaunchtype",
          "Value": "off"
        }
      }
    },
    "revert": {
      "COMMANDS": {
        "HypervisorAuto": {
          "Action": "bcdedit",
          "Name": "hypervisorlaunchtype",
          "Delete": true // bcdedit /deletevalue
        }
      }
    }
  },
  "Option Name - NVIDIA Key": {
    "apply": {
      "COMMANDS": {
        "SetNvidiaValue": {
          "Action": "nvidia_key", // searches for the NVIDIA key in the display adapter key (4d36e968-e325-11ce-bfc1-08002be10318)
          "Values": {
            "RmProfilingAdminOnly": { "Type": "REG_DWORD", "Data": 0 }
          }
        }
      }
    },
    "revert": {
      "COMMANDS": {
        "ClearNvidiaValue": {
          "Action": "nvidia_key",
          "Values": {
            "RmProfilingAdminOnly": { "Action": "deletevalue" }
          }
        }
      }
    }
  },
  "Option Name - Ethernet Key": {
    "apply": {
      "COMMANDS": {
        "SetAdapterPowerSave": {
          "Action": "ethernet_key", // searches for an active adapter (excluding VM adapters) then sets the value directly under that adapter key
          "Values": {
            "AutoPowerSaveModeEnabled": { "Type": "REG_DWORD", "Data": 0 }
          }
        },
        "SetInterfaceDnsWithNetId": {
          "Action": "ethernet_key", // gets NetCfgInstanceId from the ethernet key ({NetID})
          "NetIdPath": "HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{NetID}",
          "Values": {
            "NameServer": { "Type": "REG_SZ", "Data": "1.1.1.1" }
          }
        }
      }
    },
    "revert": {
      "COMMANDS": {
        "ResetAdapterPowerSave": {
          "Action": "ethernet_key",
          "Values": {
            "AutoPowerSaveModeEnabled": { "Action": "deletevalue" }
          }
        },
        "ResetInterfaceDnsWithNetId": {
          "Action": "ethernet_key",
          "NetIdPath": "HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{NetID}",
          "Values": {
            "NameServer": { "Action": "deletevalue" }
          }
        }
      }
    }
  },
  "Option Name - MMAgent, this was added for the Disable/Enable-MMAgent command": {
    "apply": {
      "COMMANDS": {
        "EnableMemCompr": { 
          "Action": "mmagent", 
          "Setting": "MemoryCompression", 
          "Enabled": true, 
          "Elevated": true 
        }
      }
    },
    "revert": {
      "COMMANDS": {
        "DisableMemCompr": { 
          "Action": "mmagent", 
          "Setting": "MemoryCompression", 
          "Enabled": false, 
          "Elevated": true 
        }
      }
    }
  }
}
```
