@echo off

set "minsudo=%temp%\MinSudo.exe"
curl -s -L "https://github.com/5Noxi/Files/releases/download/startmenu/MinSudo.exe" -o "%minsudo%"

echo 1 - Disable
echo 2 - Enable
echo.
set /p nvstart=

if "%nvstart%"=="1" (
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f
	"%minsudo%" -NoL -P -TI cmd /c ren "%windir%\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" "StartMenuExperienceHost.exenv"
	"%minsudo%" -NoL -P -TI cmd /c ren "%windir%\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe" "SearchHost.exenv"
	sc stop WSearch
	sc config WSearch start=disabled
	taskkill /f /im explorer.exe
	start explorer.exe
)

if "%nvstart%"=="2" (
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 1 /f
	"%minsudo%" -NoL -P -TI cmd /c ren "%windir%\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exenv" "StartMenuExperienceHost.exe"
	"%minsudo%" -NoL -P -TI cmd /c ren "%windir%\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exenv" "SearchHost.exe"
	sc config WSearch start=auto
	sc start WSearch
	taskkill /f /im explorer.exe
	start explorer.exe
)

::"%minsudo%" -NoL -P -TI cmd /c ren "%windir%\System32\ctfmon.exenv" "ctfmon.exe"