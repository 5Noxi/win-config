# Noverse Windows Configuration

This tool is based on my personal research on several topics, which I began documenting around July 2024. Initially, I uploaded them individually as messages on the [Discord server](https://discord.gg/E2ybG4j9jU), but the amount of different configurations became too large and hard to manage (and Discord isn't ideal for projects like this). If I used information from specific sources, I've included the links. Information gathered via binary string extraction, WPR, IDA, Procmon, etc. Default values from WinDbg, IDA, and stock installations. Minor mistakes or misinterpretations may exist, **corrections are welcome**.

It's based on the GitHub repository and parses it's information out of it. All [`App Tools`](https://github.com/5Noxi/app-tools)/[`Game Tools`](https://github.com/5Noxi/game-tools) are external PowerShell scripts, same goes for the [`Component Manager`](https://github.com/5Noxi/comp-mgr), [`Blocklist Manager`](https://github.com/5Noxi/blocklist-mgr) & [`Bitmask Calculator`](https://github.com/5Noxi/bitmask-calc).

## Licencing

This project is AGPL-3.0. You may copy, modify, and redistribute only if you comply with the AGPL: keep copyright and license notices, state your changes, provide the complete corresponding source (including build/installation info for user products), and license your derivative under AGPL-3.0. Any copying or redistribution outside these terms requires explicit permission. Closed-source redistribution of this code is not permitted.

## Misuse / Scam Warning

Many people repackage configs from projects like this, or from places full of misinformation, and sell them as "magic optimizers". Don't pay for such apps that hide their source and offer only vague toggles like "Optimize System Performance". It often sounds appealing to inexperienced people, but mostly contains nothing of value, as the creators are trying to make a lot of money rather than create something good. Check what a seller shares for free, if their free content already looks low effort or shows a lack of understanding, you can safely assume their paid product won't be any better. And if they refuse to share anything for free at all, you should question what their actual goal is. This is just a warning.

## My Projects

You can find all of my other projects here:
> https://5noxi.github.io/projects.html  
> https://github.com/5Noxi

More miscellaneous uploads:
> https://discord.gg/E2ybG4j9jU

## Requirements

> https://www.python.org/downloads/release/python-3130/?featured_on=pythonbytes

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
| `create_path`      | Use one: `Path` or `Paths` (array) - Optional: `File` (bool) to create a file instead of directories |
| `scheduled_task`   | Use one: `TaskName` or `TaskNames` (array) - Required: `Operation` (`run`, `stop`, `enable`, `disable`, `delete`) - Optional: `Elevated` |
| `tcp_congestion`   | Required: `Templates` (string or array), `Provider` (or `Value`) |
| `netbind`          | Required: `Components` (array or string) - Required: `State` (`enable` \| `disable`) |
| `optional_feature` | Required: `Features` (array or string) - Required: `State` (`enable` \| `disable`) - Optional: `Arguments` (array or string), `Elevated` |
| `restart_explorer` | (no arguments) |
| `bcdedit`          | Required: `Name` - One of: `Value` or `Delete`/`Remove` (bool) |
| `registry_pattern` | Required: `Pattern`, `Operations` (array) - Optional: `ExcludeSubPaths`, `ExcludePatterns`, `ExcludeSegments`, `Exclude`, `Root`, `Message` |
| `mmagent`          | Required: `Name`, desired state via one of `Enabled`/`Enable`/`State` (bool) - Optional: `Elevated` |
| `nvidia_key`       | Required: `Values` -> map of valueName -> `{ Type, Data }` (or `{ Action: "deletevalue" }`) - Optional: `SubKey` for a relative subkey, `Refresh` to rescan adapter |
| `ethernet_key`     | Required: `Values` -> map of valueName -> `{ Type, Data }` (or `{ Action: "deletevalue" }`) - Optional: `SubKey`, `Refresh` to rescan adapter, `NetIDPath` template (must contain the literal `{NetID}` placeholder) to target other hives |

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
            { "SubKey": "Settings1", "Name": "Enabled", "Type": "REG_DWORD", "Value": 1 },
            { "SubKey": "Settings2", "Name": "Channel", "Type": "REG_SZ", "Value": "Test" }
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
            { "SubKey": "Settings1", "Name": "Enabled", "Operation": "deletevalue" },
            { "SubKey": "Settings2", "Name": "Channel", "Operation": "deletevalue" }
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
            { "SubKey": "Parameters", "Name": "TraceLevel", "Operation": "deletevalue" }
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
          "Operation": "disable"
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
          "Operation": "enable"
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
          "Operation": "run" 
        },
        "StopNow": { 
          "Action": "scheduled_task", 
          "TaskName": "\\Noverse\\Telemetry Daily", 
          "Operation": "stop" 
        }
      }
    },
    "revert": {
      "COMMANDS": {
        "DeleteTask": { 
          "Action": "scheduled_task", 
          "TaskName": "\\Noverse\\Telemetry Daily", 
          "Operation": "delete" 
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
          "NetIDPath": "HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{NetID}",
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
          "NetIDPath": "HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{NetID}",
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
          "Name": "MemoryCompression", 
          "Enabled": true, 
          "Elevated": true 
        }
      }
    },
    "revert": {
      "COMMANDS": {
        "DisableMemCompr": { 
          "Action": "mmagent", 
          "Name": "MemoryCompression", 
          "Enabled": false, 
          "Elevated": true 
        }
      }
    }
  }
}
```
