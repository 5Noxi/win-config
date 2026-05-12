# Desktop Wallpaper

This is a collection of some wallpapers that I've found over time. Added for people who may never have spent time changing their background, or for anyone else. Head over to [visibility/desc.md#desktop-wallpaper](https://github.com/nohuto/win-config/blob/main/visibility/desc.md#desktop-wallpaper), if you want to see the wallpapers in a seperate window.

### Asia

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Asia.png?raw=true)

### Austria

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Austria.png?raw=true)

### Beach

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Beach.png?raw=true)

### Blue Flowers

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Blue-Flowers.png?raw=true)

### Bones

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Bones.png?raw=true)

### Castle

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Castle.png?raw=true)

### Cat

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Cat.png?raw=true)

### City

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/City.png?raw=true)

### Dark Sunset

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Dark-Sunset.png?raw=true)

### Field Sunset

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Field-Sunset.png?raw=true)

### Flowers

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Flowers.png?raw=true)

### Flowers Sunset

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Flowers-Sunset.png?raw=true)

### Golden Hour

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Golden-Hour.png?raw=true)

### Heaven

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Heaven.png?raw=true)

### Lake

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Lake.png?raw=true)

### Mac

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Mac.png?raw=true)

### Magic Forest

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Magic-Forest.png?raw=true)

### Man Landscape

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Man-Landscape.png?raw=true)

### Meadow Sunset

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Meadow-Sunset.png?raw=true)

### Moon

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Moon.png?raw=true)

### Moon Castle

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Moon-Castle.png?raw=true)

### Moon Rose

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Moon-Rose.png?raw=true)

### Mountains

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Mountains.png?raw=true)

### Plants Room

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Plants-Room.png?raw=true)

### Pokemon

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Pokemon.png?raw=true)

### Rain

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Rain.png?raw=true)

### Sea

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Sea.png?raw=true)

### Sea Road

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Sea-Road.png?raw=true)

### Shop

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Shop.png?raw=true)

### Stars

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Stars.png?raw=true)

### Stars Lake 1

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Stars-Lake-1.png?raw=true)

### Stars Lake 2

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Stars-Lake-2.png?raw=true)

### Stars Lake 3

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Stars-Lake-3.png?raw=true)

### Sunset

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Sunset.png?raw=true)

### Village

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Village.png?raw=true)

### Witcher Landscape

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Witcher-Landscape.png?raw=true)

### Workplace

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Workplace.png?raw=true)

### World

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/World.png?raw=true)

### Zelda

![](https://github.com/nohuto/win-config/blob/main/visibility/images/wallpaper/Zelda.png?raw=true)

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Desktop Wallpaper](https://www.noverse.dev/policies.html?p=Desktop*Wallpaper) | `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System` | `Wallpaper`<br>`WallpaperStyle` |

# Pointer Style

Windows has four main pointer style modes in `SystemSettings Accessibility > Mouse pointer and touch`: `White`, `Black`, `Inverted`, and `Custom color`. The first three are controlled by `CursorType`, custom colors switch `CursorType` to `6` and store the selected color in `CursorColor`. That color is stored as a Win32 [`COLORREF`](https://learn.microsoft.com/en-us/windows/win32/gdi/colorref), so the DWORD uses the `0x00bbggrr` layout instead of a plain RGB hex string. Standard styles point to system cursor files under `%SystemRoot%\cursors\...`, while custom colors point to generated per user cursor files under `%LOCALAPPDATA%\Microsoft\Windows\Cursors\*_eoa.cur`.

## Installing Custom Cursors

If you want a full custom cursor pack instead of Windows built in white, black, inverted, or recolored accessibility cursors, you can install one from diffrenrent sources such as [vsthemes.org](https://vsthemes.org/en/cursors/).

1. Download and extract the pack
2. Copy the pack files into `%SystemRoot%\Cursors\<Pack Name>` if you want to keep them in the standard system cursor location
3. Open `main.cpl`, go to the `Pointers` tab, select a cursor role, click `Browse`, and pick the downloaded `.cur` or `.ani` file

## Cursor Previews

| Name | Preview |
|--|--|
| Custom colors + dark/light/invert | ![](https://github.com/nohuto/win-config/blob/main/visibility/images/cursors/defaults.png?raw=true) |
| [Simplify Dot](https://vsthemes.org/en/cursors/static/47356-simplify-dot-2.html) (Dark/Light) | ![](https://github.com/nohuto/win-config/blob/main/visibility/images/cursors/simplify-dot.webp?raw=true) |
| [Colloid Dark](https://vsthemes.org/en/cursors/black/68372-colloid-dark.html) | ![](https://github.com/nohuto/win-config/blob/main/visibility/images/cursors/colloid-dark.webp?raw=true) |
| [Colloid Light](https://vsthemes.org/en/cursors/white/68371-colloid-light.html) | ![](https://github.com/nohuto/win-config/blob/main/visibility/images/cursors/colloid-light.webp?raw=true) |
| [Monolith](https://vsthemes.org/en/cursors/black/70650-monolith.html) (Dark/Light) | ![](https://github.com/nohuto/win-config/blob/main/visibility/images/cursors/monolith.webp?raw=true) |
| [Capitaine](https://vsthemes.org/en/cursors/black/27320-capitaine.html) (Dark, White, Gruvbox, Gruvbox White, Nord, Nord White, Palenight, Palenight White) | ![](https://github.com/nohuto/win-config/blob/main/visibility/images/cursors/capitaine.webp?raw=true) |
| [Skyrim](https://vsthemes.org/en/cursors/games/45588-the-elder-scrolls-5-skyrim.html) | ![](https://github.com/nohuto/win-config/blob/main/visibility/images/cursors/skyrim.webp?raw=true) |

## Pointer Style Captures

```c
// Main style
// 0 = White, 1 = Black, 2 = Inverted, 6 = Custom color
HKCU\Software\Microsoft\Accessibility\CursorType	Type: REG_DWORD

// Custom color only (COLORREF format: 0x00bbggrr)
HKCU\Software\Microsoft\Accessibility\CursorColor	Type: REG_DWORD

// Standard styles use the built in system cursor sets
HKCU\Control Panel\Cursors\(Default)		Type: REG_SZ
HKCU\Control Panel\Cursors\Arrow		Type: REG_EXPAND_SZ
HKCU\Control Panel\Cursors\Help		Type: REG_EXPAND_SZ
HKCU\Control Panel\Cursors\AppStarting	Type: REG_EXPAND_SZ
HKCU\Control Panel\Cursors\Wait		Type: REG_EXPAND_SZ
HKCU\Control Panel\Cursors\Crosshair	Type: REG_EXPAND_SZ
HKCU\Control Panel\Cursors\IBeam		Type: REG_EXPAND_SZ
HKCU\Control Panel\Cursors\NWPen		Type: REG_EXPAND_SZ
HKCU\Control Panel\Cursors\No		Type: REG_EXPAND_SZ
HKCU\Control Panel\Cursors\SizeNS		Type: REG_EXPAND_SZ
HKCU\Control Panel\Cursors\SizeWE		Type: REG_EXPAND_SZ
HKCU\Control Panel\Cursors\SizeNWSE	Type: REG_EXPAND_SZ
HKCU\Control Panel\Cursors\SizeNESW	Type: REG_EXPAND_SZ
HKCU\Control Panel\Cursors\SizeAll		Type: REG_EXPAND_SZ
HKCU\Control Panel\Cursors\UpArrow	Type: REG_EXPAND_SZ
HKCU\Control Panel\Cursors\Hand		Type: REG_EXPAND_SZ
HKCU\Control Panel\Cursors\Scheme Source	Type: REG_DWORD

// Custom colored styles use generated peruser cursor files
HKCU\Control Panel\Cursors\Arrow // %LOCALAPPDATA%\Microsoft\Windows\Cursors\arrow_eoa.cur
HKCU\Control Panel\Cursors\AppStarting // %LOCALAPPDATA%\Microsoft\Windows\Cursors\busy_eoa.cur
HKCU\Control Panel\Cursors\Crosshair // %LOCALAPPDATA%\Microsoft\Windows\Cursors\cross_eoa.cur
HKCU\Control Panel\Cursors\Hand // %LOCALAPPDATA%\Microsoft\Windows\Cursors\link_eoa.cur
HKCU\Control Panel\Cursors\Help // %LOCALAPPDATA%\Microsoft\Windows\Cursors\helpsel_eoa.cur
HKCU\Control Panel\Cursors\IBeam // %LOCALAPPDATA%\Microsoft\Windows\Cursors\ibeam_eoa.cur
HKCU\Control Panel\Cursors\No // %LOCALAPPDATA%\Microsoft\Windows\Cursors\unavail_eoa.cur
HKCU\Control Panel\Cursors\NWPen // %LOCALAPPDATA%\Microsoft\Windows\Cursors\pen_eoa.cur
HKCU\Control Panel\Cursors\Person // %LOCALAPPDATA%\Microsoft\Windows\Cursors\person_eoa.cur
HKCU\Control Panel\Cursors\Pin // %LOCALAPPDATA%\Microsoft\Windows\Cursors\pin_eoa.cur
HKCU\Control Panel\Cursors\SizeAll // %LOCALAPPDATA%\Microsoft\Windows\Cursors\move_eoa.cur
HKCU\Control Panel\Cursors\SizeNESW // %LOCALAPPDATA%\Microsoft\Windows\Cursors\nesw_eoa.cur
HKCU\Control Panel\Cursors\SizeNS // %LOCALAPPDATA%\Microsoft\Windows\Cursors\ns_eoa.cur
HKCU\Control Panel\Cursors\SizeNWSE // %LOCALAPPDATA%\Microsoft\Windows\Cursors\nwse_eoa.cur
HKCU\Control Panel\Cursors\SizeWE // %LOCALAPPDATA%\Microsoft\Windows\Cursors\ew_eoa.cur
HKCU\Control Panel\Cursors\UpArrow // %LOCALAPPDATA%\Microsoft\Windows\Cursors\up_eoa.cur
HKCU\Control Panel\Cursors\Wait // %LOCALAPPDATA%\Microsoft\Windows\Cursors\wait_eoa.cur
HKCU\Control Panel\Cursors\CursorBaseSize	Type: REG_DWORD

// Used custom color DWORDs (these are the predefined ones from SystemSettings)
HKCU\Software\Microsoft\Accessibility\CursorColor = 16711871	// Pink (0x00FF00BF)
HKCU\Software\Microsoft\Accessibility\CursorColor = 65471		// Lime (0x0000FFBF)
HKCU\Software\Microsoft\Accessibility\CursorColor = 64250		// Yellow (0x0000FAFA)
HKCU\Software\Microsoft\Accessibility\CursorColor = 49151		// Gold (0x0000BFFF)
HKCU\Software\Microsoft\Accessibility\CursorColor = 12517631	// Pink (0x00BF00FF)
HKCU\Software\Microsoft\Accessibility\CursorColor = 16760576	// Turquise (0x00FFBF00)
HKCU\Software\Microsoft\Accessibility\CursorColor = 12582656	// Green (0x00BFFF00)
```

*Note: when applying these manually via the registry the cursor can be refreshed using [SPI_SETCURSORS](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfoa), this only works for dark+light+inverted+custom, the color ones build `*_eoa.cur` files as said above which the function doesn't do (which is also kind of why the dropdown doesn't include colored cursors).

# Disable Rounded Corners

This currently works via [Win11DisableRoundedCorners](https://github.com/valinet/Win11DisableRoundedCorners) which works fine on [latest version since the function exists/works the same on latest builds](https://www.noverse.dev/bin-diff.html). Note that the revert doesn't run `sfc /scannow` to restore proper file permissions to `uDWM.dll` since it does a lot more than restoring permissions. If you're aware if it, run the command after reverting the option.

It works by overriding the first 8 bytes in the function with `48 C7 C0 00 00 00 00 C3`:

```c
mov rax, 0; ret // result = 0
```

### Rounded Corners

![](https://github.com/nohuto/win-config/blob/main/visibility/images/rounded.png?raw=true)

### Angular Corners

![](https://github.com/nohuto/win-config/blob/main/visibility/images/angular.png?raw=true)

## [GetEffectiveCornerStyle](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/uDWM/-GetEffectiveCornerStyle%40CTopLevelWindow%40%40AEAA-AW4CORNER_STYLE%40%40XZ.c)

That function calculates the effective corner mode, its callers include border/shadow/radius.
```c
/*
 * XREFs of ?GetEffectiveCornerStyle@CTopLevelWindow@@AEAA?AW4CORNER_STYLE@@XZ @ 0x18003AB74
 * Callers:
 *     ?GetShadowStyle@CTopLevelWindow@@AEAA?AW4ShadowStyle@CWindowBorder@@XZ @ 0x18001AA04 (-GetShadowStyle@CTopLevelWindow@@AEAA-AW4ShadowStyle@CWindowBorder@@XZ.c)
 *     ?UpdateWindowVisuals@CTopLevelWindow@@AEAAJXZ @ 0x18003D8E0 (-UpdateWindowVisuals@CTopLevelWindow@@AEAAJXZ.c)
 *     ?GetRadiusFromCornerStyle@CTopLevelWindow@@AEAAMXZ @ 0x1800E5B98 (-GetRadiusFromCornerStyle@CTopLevelWindow@@AEAAMXZ.c)
 * Callees:
 *     IsOpenThemeDataPresent @ 0x18005DB28 (IsOpenThemeDataPresent.c)
 */

__int64 __fastcall CTopLevelWindow::GetEffectiveCornerStyle(__int64 a1)
{
  __int64 result; // rax
  int v2; // ebx

  if ( *((_BYTE *)CDesktopManager::s_pDesktopManagerInstance + 27)
    && !*((_BYTE *)CDesktopManager::s_pDesktopManagerInstance + 29)
    || *((int *)CDesktopManager::s_pDesktopManagerInstance + 8) >= 2 )
  {
    return 1LL;
  }
  result = *(unsigned int *)(*(_QWORD *)(a1 + 752) + 184LL);
  if ( !(_DWORD)result )
  {
    v2 = *(_DWORD *)(a1 + 624);
    if ( (v2 & 2) != 0 )
      return 3LL;
    if ( !(unsigned __int8)IsOpenThemeDataPresent() )
      return 1LL;
    result = 2LL;
    if ( (v2 & 6) == 0 )
      return 1LL;
  }
  return result;
}
```

Obviously, `GetEffectiveCornerStyle` only exists in W11 builds (as you can see in [decompiled-pseudocode](https://github.com/nohuto/decompiled-pseudocode)).

# Optimize Visual Effects

Disables all kind of animations, while leaving font smoothing + window content while dragging + thumbnails instead of icons enabled.

## UserPreferencesMask

Anything written as "- *text*" behind the linked name equals the source where the option can be toggled (and where I recorded the bit differences), "(untested)" means that I didn't find the Windows UI toggle for the bit yet, means that the meaning is currently based on pseudocode, or on [SystemParametersInfo (`SPI_*`)](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow) naming. All meanings have a link to the win32k pseudocode function where the bit is read.

| Bit | Hex | Meaning |
| --- | --- | --- |
| 0 | `0x00000001` | [Active window tracking (untested)](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/-xxxTrackingActivateWindow@@YA_NPEAUtagWND@@@Z.c) |
| 1 | `0x00000002` | [Fade or slide menus into view](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/xxxMenuWindowProc.c) - *Performance Options* |
| 2 | `0x00000004` | [Slide open combo boxes](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/xxxSystemParametersInfoWorker.c) - *Performance Options* |
| 3 | `0x00000008` | [Smooth-scroll list boxes](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/xxxSystemParametersInfoWorker.c) - *Performance Options* |
| 4 | `0x00000010` | [Caption/gradient visual effects (untested)](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/-xxxAnimateCaption@@YAXPEAUtagWND@@PEAUHDC__@@PEAUtagRECT@@2@Z.c) - "When set, each window title bar has a gradient effect (changes from one color or shade to another along the length of the title bar)." |
| 5 | `0x00000020` | [Keyboard cues / menu underlines (untested)](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/-xxxDrawMenuItemText@@YAXAEBV-$SmartObjStackRef@UtagMENU@@@@PEAUtagITEM@@PEAUHDC__@@HHPEAGHH@Z.c) |
| 6 | `0x00000040` | [Active window tracking Z-order (untested)](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/-xxxTrackingActivateWindow@@YA_NPEAUtagWND@@@Z.c) |
| 7 | `0x00000080` | [Hot tracking (untested)](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/xxxTrackMouseMove.c) |
| 9 | `0x00000200` | [Menu fade (untested)](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/ShouldHaveShadow.c), requires bit `1` to be set |
| 10 | `0x00000400` | [Fade out menu items after clicking](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/-zzzMNFadeSelection@@YAHAEBV-$SmartObjStackRef@UtagMENU@@@@PEAUtagITEM@@@Z.c) - *Performance Options* |
| 11 | `0x00000800` | [Fade or slide ToolTips into view](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/-xxxShowTooltip@@YAHPEAUtagTOOLTIPWND@@@Z.c) - *Performance Options* |
| 12 | `0x00001000` | [Tooltip fade (untested)](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/xxxTooltipWndProc.c), required bit `11` to be set |
| 13 | `0x00002000` | [Show shadows under mouse pointer](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/-FCursorShadowed@@YA_NPEAU_CURSINFO@@@Z.c) - *Performance Options* |
| 14 | `0x00004000` | [Show location of pointer when I press the CTRL key](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/EditionHandleSonarKeyEvent.c) - *Mouse Properties* |
| 15 | `0x00008000` | [Turn on ClickLock](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kbase/-ProcessMouseButton@CMouseProcessor@@AEAAXAEBVCButtonEvent@1@@Z.c) - *Mouse Properties* |
| 16 | `0x00010000` | [Hide pointer while typing](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/NtUserHideCursorNoCapture.c) - *Mouse Properties* |
| 17 | `0x00020000` | [Flat menus (untested)](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/xxxDrawMenuBarUnderlines.c) |
| 18 | `0x00040000` | [Show shadows under windows](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/ShouldHaveShadow.c) - *Performance Options* |
| 31 | `0x80000000` | [Master UI effects (untested)](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/xxxSystemParametersInfoWorker.c) - "When enabled, all user interface effects (combo box animation, cursor shadow, gradient captions, hot tracking, list box smooth scrolling, menu animation, menu underlines, selection fade, tool tip animation) are enabled." |
| 33 | `0x00000002` in high dword | Animate controls and elements inside windows |
| 39 | `0x00000080` in high dword | [Suppress/apply global input-settings updates on focus/delegation changes (untested)](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/EditionKeyboardInputDelegationChanged.c) |
| 41 | `0x00000200` in high dword | [Pen button yield / pen quick-launch hotkey (untested)](https://github.com/nohuto/decompiled-pseudocode/blob/main/11-23H2/win32kfull/-NotifyISMPenButtonYieldSettingChange@@YAXXZ.c) |

## Font Smoothing

![](https://github.com/nohuto/win-config/blob/main/visibility/images/visual1.jpg?raw=true)

# Enable Dark Theme

See [`darktheme-GetThemeFromUnattendSetup.c`](https://github.com/nohuto/win-config/blob/main/visibility/assets/darktheme-GetThemeFromUnattendSetup.c) for information about the comments, otherwise ignore it.

### Light Theme

![](https://github.com/nohuto/win-config/blob/main/visibility/images/darktheme1.png?raw=true)

### Dark Theme

![](https://github.com/nohuto/win-config/blob/main/visibility/images/darktheme2.png?raw=true)

# Disable Transparency

### Transparency Enabled

![](https://github.com/nohuto/win-config/blob/main/visibility/images/transpa1.png?raw=true)

### Transparency Disabled

![](https://github.com/nohuto/win-config/blob/main/visibility/images/transpa2.png?raw=true)

# Disable Animations

Minimize, Maximize, Taskbar Animations / First Sign-In Animations. These options are also changeable via `SystemPropertiesPerformance` (`WIN + R`) - first three.

`MaxAnimate` doesn't exist, windows only uses `MinAnimate`
```
SystemPropertiesAdvanced.exe	RegSetValue	HKCU\Control Panel\Desktop\WindowMetrics\MinAnimate	Type: REG_SZ, Length: 4, Data: 1
```
Disable logon animations, which would remove the animation (picture), instead shows the windows default background wallpaper: (first sign-in):
```
This policy controls whether users see the first sign-in animation when signing in for the first time, including both the initial setup user and those added later. It also determines if Microsoft account users receive the opt-in prompt for services. If enabled, Microsoft account users see the opt-in prompt and other users see the animation. If disabled, neither the animation nor the opt-in prompt appears. If not configured, the first user sees the animation during setup; later users won't see it if setup was already completed. This policy has no effect on Server editions.
```

Second one is used by Windows (`Computer Configuration > Administrative Templates > System > Logon : Show first sign-in animation`), see [visibility/assets | animation-WinMain.c](https://github.com/nohuto/win-config/blob/main/visibility/assets/animation-WinMain.c) for more:
```c
CMachine::RegQueryDWORD(
  v62,
  L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
  L"EnableFirstLogonAnimation",
  0,
  &v117);
v118 = 1;

CMachine::RegQueryDWORD(
  v63,
  L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
  L"EnableFirstLogonAnimation",
  1u,
  &v118);
```
`AnimationAfterUserOOBE` & `SkipNextFirstLogonAnimation` (`CurrentVersion\Winlogon`) also exist.

![](https://github.com/nohuto/win-config/blob/main/visibility/images/animation.png?raw=true)

`ForceDisableModeChangeAnimation` got added in [22621.3807/22631.3807](https://blogs.windows.com/windows-insider/2024/06/13/releasing-windows-11-builds-22621-3807-and-22631-3807-to-the-release-preview-channel/) and is used for "When you set its value to 1 (or a non-zero number), it turns off the display mode change animation. If the value is 0 or the key does not exist, the animation is set to on."

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Do not allow window animations](https://www.noverse.dev/policies.html?p=DWM*DwmDisallowAnimations_1) | `HKCU\SOFTWARE\Policies\Microsoft\Windows\DWM` | `DisallowAnimations` |
| [Do not allow window animations](https://www.noverse.dev/policies.html?p=DWM*DwmDisallowAnimations_2) | `HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM` | `DisallowAnimations` |
| [Turn off common control and window animations](https://www.noverse.dev/policies.html?p=Explorer*TurnOffSPIAnimations) | `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` | `TurnOffSPIAnimations` |
| [Show first sign-in animation](https://www.noverse.dev/policies.html?p=Logon*EnableFirstLogonAnimation) | `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System` | `EnableFirstLogonAnimation` |

# Explorer Options

It changes every setting, which is shown in the `Folder Options` window. Some are personal preference, see suboptions bellow for customization.

![](https://github.com/nohuto/win-config/blob/main/visibility/images/explorer.png?raw=true)

## Miscellaneous Notes

```json
"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer": {
  "ShellState": { "Type": "REG_BINARY", "Data": "240000003e20000000000000000000000001000000130000000000000042000000" }
},
"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CabinetState": {
  "Settings": { "Type": "REG_BINARY", "Data": "0c0002000a01000060000000" }
}
```

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Hide and disable all items on the desktop](https://www.noverse.dev/policies.html?p=Desktop*NoDesktop) | `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`<br>`HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` | `NoDesktop` |
| [Do not keep history of recently opened documents](https://www.noverse.dev/policies.html?p=StartMenu*NoRecentDocsHistory) | `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`<br>`HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` | `NoRecentDocsHistory` |
| [Prohibit access of the Windows Connect Now wizards](https://www.noverse.dev/policies.html?p=WindowsConnectNow*WCN_DisableWcnUi_2) | `HKLM\Software\Policies\Microsoft\Windows\WCN\UI` | `DisableWcnUi` |

# Taskbar Settings

Removes the search box, moves the taskbar to the left, removes badges, disables the flashes on the app icons, removes the "Task View" button. (`Personalization > Taskbar`)

`TaskbarSd` adds/removes the block in the right corner, which shows the desktop (picture).

![](https://github.com/nohuto/win-config/blob/main/visibility/images/taskbar.png?raw=true)

```json
"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced": {
  "TaskbarDa": { "Type": "REG_DWORD", "Data": 0, "Elevated": true },
```
I removed the value since you can't apply it even with `TrustedInstaller`/`SYSTEM` previledges. Note that the value is still actively used by `SystemSettings`:
```c
// Personalization > Taskbar - Widgets (off)
SystemSettings.exe	HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDa	Type: REG_DWORD, Length: 4, Data: 0
```
Disallowing it via the `AllowNewsAndInterests` policy won't set `TaskbarDa` to 0, but it grays out & disables the option.

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Allow widgets](https://www.noverse.dev/policies.html?p=NewsAndInterests*AllowNewsAndInterests) | `HKLM\SOFTWARE\Policies\Microsoft\Dsh` | `AllowNewsAndInterests` |
| [Disable Widgets On Lock Screen](https://www.noverse.dev/policies.html?p=NewsAndInterests*DisableWidgetsOnLockScreen) | `HKLM\SOFTWARE\Policies\Microsoft\Dsh` | `DisableWidgetsOnLockScreen` |
| [Disable Widgets Board](https://www.noverse.dev/policies.html?p=NewsAndInterests*DisableWidgetsBoard) | `HKLM\SOFTWARE\Policies\Microsoft\Dsh` | `DisableWidgetsBoard` |
| [Remove the People Bar from the taskbar](https://www.noverse.dev/policies.html?p=StartMenu*HidePeopleBar) | `HKCU\Software\Policies\Microsoft\Windows\Explorer` | `HidePeopleBar` |
| [Hide the TaskView button](https://www.noverse.dev/policies.html?p=Taskbar*HideTaskViewButton) | `HKLM\Software\Policies\Microsoft\Windows\Explorer`<br>`HKCU\Software\Policies\Microsoft\Windows\Explorer` | `HideTaskViewButton` |

# Accent Color

This set's the accent color globally and if `AccentColor` (`HKEY_CURRENT_USER\Software\Noverse`) isn't set via the tool settings yet, this will also directly impact the WinConfig colors.

`Show Accent Color on Start and Taskbar` only works if using dark theme.

Something I noticed while creating the option is that procmon doesn't show the actual used binary data:
```c
// Procmon
59657CFF4A5468FF3F4859FF353C4AFF // 16

// After refreshing
59657CFF4A5468FF3F4859FF353C4AFF2A303BFF1F242CFF111317FF88179800 // 32

// Procmon
99EBFF004CC2FF000091F8000078D400

// After refreshing
99EBFF004CC2FF000091F8000078D4000067C000003E9200001A6800F7630C00
```

## SystemSettings Captures

Changing the color via `Personalization > Colors` sets:
```c
// Nord Theme (#2e3440)
HKCU\Software\Microsoft\Windows\DWM\ColorizationColor	Type: REG_DWORD, Length: 4, Data: 3291823178
HKCU\Software\Microsoft\Windows\DWM\ColorizationAfterglow	Type: REG_DWORD, Length: 4, Data: 3291823178
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent\AccentPalette	Type: REG_BINARY, Length: 32, Data: 59 65 7C FF 4A 54 68 FF 3F 48 59 FF 35 3C 4A FF // see note above
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent\StartColorMenu	Type: REG_DWORD, Length: 4, Data: 4282069034
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent\AccentColorMenu	Type: REG_DWORD, Length: 4, Data: 4283055157
HKCU\Software\Microsoft\Windows\DWM\AccentColor	Type: REG_DWORD, Length: 4, Data: 4283055157
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SystemProtectedUserData\S-1-5-21-1713887642-2553820887-3827158055-1000\AnyoneRead\Colors\StartColor	Type: REG_DWORD, Length: 4, Data: 4282069034
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SystemProtectedUserData\S-1-5-21-1713887642-2553820887-3827158055-1000\AnyoneRead\Colors\AccentColor	Type: REG_DWORD, Length: 4, Data: 4283055157

// Default Blue
HKCU\Software\Microsoft\Windows\DWM\ColorizationColor	Type: REG_DWORD, Length: 4, Data: 3288365268
HKCU\Software\Microsoft\Windows\DWM\ColorizationAfterglow	Type: REG_DWORD, Length: 4, Data: 3288365268
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent\AccentPalette	Type: REG_BINARY, Length: 32, Data: 99 EB FF 00 4C C2 FF 00 00 91 F8 00 00 78 D4 00
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent\StartColorMenu	Type: REG_DWORD, Length: 4, Data: 4290799360
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent\AccentColorMenu	Type: REG_DWORD, Length: 4, Data: 4292114432
HKCU\Software\Microsoft\Windows\DWM\AccentColor	Type: REG_DWORD, Length: 4, Data: 4292114432
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SystemProtectedUserData\S-1-5-21-1713887642-2553820887-3827158055-1000\AnyoneRead\Colors\StartColor	Type: REG_DWORD, Length: 4, Data: 4290799360
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SystemProtectedUserData\S-1-5-21-1713887642-2553820887-3827158055-1000\AnyoneRead\Colors\AccentColor	Type: REG_DWORD, Length: 4, Data: 4292114432
```

# Account Picture

Changes the user account picture via:
```
C:\ProgramData\Microsoft\Default Account Pictures
```

### Suboption

`Global Account Picture`:  
"This policy setting allows an administrator to standardize the account pictures for all users on a system to the default account picture."

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Apply the default account picture to all users](https://www.noverse.dev/policies.html?p=Cpls*UseDefaultTile) | `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` | `UseDefaultTile` |

# System Fonts

W11 uses `Segoe UI` by default. You can change it via registry edits, the selected font will be used for desktop interfaces, explorer, some apps (`StartAllBack` will use it), but won't get applied for e.g., `SystemSettings.exe` and app fonts in general. Some fonts will cause issues - `Yu Gothic UI Light` uses `¥` instead of `\` (picture).

Either select a installed font with the command shown below or install new fonts via e.g. [nerdfonts](https://www.nerdfonts.com/font-downloads).

Applying a new font needs a restart or logout, reverting doesn't.
```powershell
shutdown -l # logout
```

List all available font families on your system with the `Open` option, or via `Personalization > Fonts`:
```powershell
Add-Type -AssemblyName System.Drawing;[System.Drawing.FontFamily]::Families | % {$_.Name}
```

![](https://github.com/nohuto/win-config/blob/main/visibility/images/font1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/visibility/images/font2.png?raw=true)

## Manually Adding Custom Fonts

The option lists the default fonts, add your own custom font via:
```json
"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts": {
  "Segoe UI (TrueType)": { "Type": "REG_SZ", "Data": "" },
  "Segoe UI Black (TrueType)": { "Type": "REG_SZ", "Data": "" },
  "Segoe UI Black Italic (TrueType)": { "Type": "REG_SZ", "Data": "" },
  "Segoe UI Bold (TrueType)": { "Type": "REG_SZ", "Data": "" },
  "Segoe UI Bold Italic (TrueType)": { "Type": "REG_SZ", "Data": "" },
  "Segoe UI Historic (TrueType)": { "Type": "REG_SZ", "Data": "" },
  "Segoe UI Italic (TrueType)": { "Type": "REG_SZ", "Data": "" },
  "Segoe UI Light (TrueType)": { "Type": "REG_SZ", "Data": "" },
  "Segoe UI Light Italic (TrueType)": { "Type": "REG_SZ", "Data": "" },
  "Segoe UI Semibold (TrueType)": { "Type": "REG_SZ", "Data": "" },
  "Segoe UI Semibold Italic (TrueType)": { "Type": "REG_SZ", "Data": "" },
  "Segoe UI Semilight (TrueType)": { "Type": "REG_SZ", "Data": "" },
  "Segoe UI Semilight Italic (TrueType)": { "Type": "REG_SZ", "Data": "" },
  "Segoe UI Symbol (TrueType)": { "Type": "REG_SZ", "Data": "" }
}
// "Font Name" = Replace with the font name
"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes": {
  "Segoe UI": { "Type": "REG_SZ", "Data": "Font Name" }
}
```

Revert the changes:
```json
"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts": {
  "Segoe UI (TrueType)": { "Type": "REG_SZ", "Data": "segoeui.ttf" },
  "Segoe UI Black (TrueType)": { "Type": "REG_SZ", "Data": "seguibl.ttf" },
  "Segoe UI Black Italic (TrueType)": { "Type": "REG_SZ", "Data": "seguibli.ttf" },
  "Segoe UI Bold (TrueType)": { "Type": "REG_SZ", "Data": "segoeuib.ttf" },
  "Segoe UI Bold Italic (TrueType)": { "Type": "REG_SZ", "Data": "segoeuiz.ttf" },
  "Segoe UI Historic (TrueType)": { "Type": "REG_SZ", "Data": "seguihis.ttf" },
  "Segoe UI Italic (TrueType)": { "Type": "REG_SZ", "Data": "segoeuii.ttf" },
  "Segoe UI Light (TrueType)": { "Type": "REG_SZ", "Data": "segoeuil.ttf" },
  "Segoe UI Light Italic (TrueType)": { "Type": "REG_SZ", "Data": "seguili.ttf" },
  "Segoe UI Semibold (TrueType)": { "Type": "REG_SZ", "Data": "seguisb.ttf" },
  "Segoe UI Semibold Italic (TrueType)": { "Type": "REG_SZ", "Data": "seguisbi.ttf" },
  "Segoe UI Semilight (TrueType)": { "Type": "REG_SZ", "Data": "segoeuisl.ttf" },
  "Segoe UI Semilight Italic (TrueType)": { "Type": "REG_SZ", "Data": "seguisli.ttf" },
  "Segoe UI Symbol (TrueType)": { "Type": "REG_SZ", "Data": "seguisym.ttf" }
},
"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes": {
  "Segoe UI": { "Action": "deletevalue" }
}
```

## Suboptions

| Option | Description |
| --- | --- |
| Hide fonts based on language settings | "Windows can hide fonts that are not designed for your input language settings. If you choose this option, only fonts that are designed for your language settings will be listed in your programs. |
| Allow fonts to be installed using a shortcut | To save space on your computer, you can choose to install a shortcut to a font file instead of the file itself. If the font file becomes unavailable, you might not be able to use the font. |

## Notes on System Text Size

Edit text sizes via [`TextScaleFactor`](https://learn.microsoft.com/en-us/uwp/api/windows.ui.viewmanagement.uisettings.textscalefactor?view=winrt-26100#windows-ui-viewmanagement-uisettings-textscalefactor), valid ranges are `100-225` (DWORD).

```c
  v10 = 0;
  if ( (int)SHRegGetDWORD(HKEY_CURRENT_USER, L"Software\\Microsoft\\Accessibility", L"TextScaleFactor", &v10) < 0
    || (v6 = v10, v10 - 101 > 0x7C) ) // valid range: [101, 225] -> v10 - 101 > 124  -> v10 > 225
  {
    v6 = 100LL; // fallback to 100 if missing or out of range (<100 / >225)
  }
```
- [visibility/assets | textsize-TextScaleDialogTemplate.c](https://github.com/nohuto/win-config/blob/main/visibility/assets/textsize-TextScaleDialogTemplate.c)

Applying changes via `Accessibility > Text size`:
```c
// 100%
RegSetValue    HKCU\Software\Microsoft\Accessibility\TextScaleFactor    Type: REG_DWORD, Length: 4, Data: 100

// 225%
RegSetValue    HKCU\Software\Microsoft\Accessibility\TextScaleFactor    Type: REG_DWORD, Length: 4, Data: 225
```
Depending on the selected size, `CaptionFont`, `SmCaptionFont`, `MenuFont`, `StatusFont`, `MessageFont`, `IconFont` (located in `HKCU\Control Panel\Desktop\WindowMetrics`) will also change. Not every % increase will edit them, I may add exact data soon. Example of `100%`/`225%`:

```c
// 100%
IconFont    Type: REG_BINARY, Length: 92, Data: F4 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
CaptionFont    Type: REG_BINARY, Length: 92, Data: F4 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
SmCaptionFont    Type: REG_BINARY, Length: 92, Data: F4 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
MenuFont    Type: REG_BINARY, Length: 92, Data: F4 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
StatusFont    Type: REG_BINARY, Length: 92, Data: F4 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
MessageFont    Type: REG_BINARY, Length: 92, Data: F4 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00

// 225%
CaptionFont    Type: REG_BINARY, Length: 92, Data: E5 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
SmCaptionFont    Type: REG_BINARY, Length: 92, Data: E5 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
MenuFont    Type: REG_BINARY, Length: 92, Data: E5 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
StatusFont    Type: REG_BINARY, Length: 92, Data: E5 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
MessageFont    Type: REG_BINARY, Length: 92, Data: E5 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
IconFont    Type: REG_BINARY, Length: 92, Data: E5 FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
```

# Mouse Hover Time

`MouseHoverTime` controls how long the mouse must stay still over something before Windows treats it as a hover.

`MenuShowDelay` controls the menu hover delay, mainly how long shell menus wait before opening a submenu while the pointer is on a menu entry.

## CMenuToolbarBase::_SetTimer

[`SPI_GETMENUSHOWDELAY`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfoa):
> "*Retrieves the time, in milliseconds, that the system waits before displaying a shortcut menu when the mouse cursor is over a submenu item. The pvParam parameter must point to a DWORD variable that receives the time of the delay.*"

```c
if ( SystemParametersInfoW(0x6Au, 0, &g_lMenuPopupTimeout, 0) ) // 0x6A = SPI_GETMENUSHOWDELAY
  goto LABEL_5;
v4 = g_lMenuPopupTimeout;
if ( g_lMenuPopupTimeout != -1 )
  goto LABEL_6;
g_lMenuPopupTimeout = 4 * GetDoubleClickTime() / 5; // fallback (depends on DoubleClickSpeed)
if ( SHRegGetStringEx(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"MenuShowDelay", 2u, pszSrc, 6u) < 0 ) // 2u = REG_SZ
{
LABEL_5:
  v4 = g_lMenuPopupTimeout;
}
else
{
  v4 = StrToIntW(pszSrc);
  g_lMenuPopupTimeout = v4;
}
```

It first uses [`SystemParametersInfoW(SPI_GETMENUSHOWDELAY)`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfoa), so the registry value is normally used through the API. If that API fails and no cached value exists, it falls back to `4 * GetDoubleClickTime() / 5`, means the fallback depends on the current double click speed (`HKCU\Control Panel\Mouse\DoubleClickSpeed`). By default it's set to `500 ms` = fallback becomes `400 ms`.

```c
if ( (_DWORD)v2 == 32771 )
  goto LABEL_19;
if ( (_DWORD)v2 != 32776 )
{
  if ( (_DWORD)v2 != 32777 )
  {
    if ( (_DWORD)v2 == 32778 )
    {
      v4 = 60000; // fixed 60 seconds
    }
    else if ( (_DWORD)v2 == 32779 )
    {
      v4 = 2 * GetDoubleClickTime(); // ignores MenuShowDelay
    }
    return SetTimer(this[2], v2, v4, 0LL); // v4 = uElapse
  }
LABEL_19:
  v4 *= 2;
  if ( v4 < 2000 )
    v4 = 2000;
  return SetTimer(this[2], v2, v4, 0LL); // v4 = uElapse
}
if ( ((_BYTE)this[15] & 1) == 0 )
  return 1LL;
v5 = *((_QWORD *)this[5] + 34);
if ( !v5 || (*(_BYTE *)(v5 + 72) & 1) != 0 || ((_BYTE)this[15] & 0x20) != 0 )
  return 1LL;
v4 *= 5;
if ( v4 < 2000 )
  v4 = 2000;
return SetTimer(this[2], v2, v4, 0LL); // v4 = uElapse
```

`v4` is the final value passed to [`SetTimer`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-settimer) as `uElapse`, which can be used as maximum I guess (as the part above doesn't show any max clamp) values below `USER_TIMER_MINIMUM` (`10 ms`) are increased to `10 ms`, values above `USER_TIMER_MAXIMUM` (`0x7FFFFFFF`, `~24.8 days`) are lowered to that maximum. Obviously, that's just my current interpretation, and I don't claim that it's the truth.

The normal menu hover timers use `MenuShowDelay`, some menu timers ignore or extend it, `32771` & `32777` use at least `2 seconds`, `32776` can use at least `2 seconds` after multiplying the value by `5`, `32778` is fixed to `60 seconds`, `32779` uses double click time instead.

# Disable Audio / Video Preview

Disables the preview function for (extensions):
```
3gp aac avi flac m4a m4v mkv mod mov mp3 mp4 mpeg mpg ogg ts vob wav webm wma wmv
```
[`{E357FCCD-A995-4576-B01F-234630154E96}`](https://learn.microsoft.com/en-us/windows/win32/shell/handlers#handler-names) - Thumbnail Provider (Thumbnail image handler)
[`{BB2E617C-0920-11D1-9A0B-00C04FC2D6C1}`](https://learn.microsoft.com/en-us/windows/win32/shell/handlers#handler-names) - Extract Image (Image handler)
[`{9DBD2C50-62AD-11D0-B806-00C04FD706EC}`](https://learn.microsoft.com/en-us/windows/win32/shell/handlers#handler-names) - Default shell extension handler for thumbnails

### Enabled

![](https://github.com/nohuto/win-config/blob/main/visibility/images/audiovidpreon.png?raw=true)

### Disabled

![](https://github.com/nohuto/win-config/blob/main/visibility/images/audiovidpreonoff.png?raw=true)

---

Hide preview pane:
```powershell
"Explorer.EXE","RegSetValue","HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Modules\GlobalSettings\Sizer\DetailsContainerSizer","Type: REG_BINARY, Length: 16, Data: 15 01 00 00 00 00 00 00 00 00 00 00 6B 03 00 00"
"Explorer.EXE","RegSetValue","HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Modules\GlobalSettings\DetailsContainer\DetailsContainer","Type: REG_BINARY, Length: 8, Data: 02 00 00 00 02 00 00 00"
```

# Classic Context Menu

Use it on W11, unless you like the new menu.

### Before

![](https://github.com/nohuto/win-config/blob/main/visibility/images/classiconb.png?raw=true)

### After

![](https://github.com/nohuto/win-config/blob/main/visibility/images/classicona.png?raw=true)

# Disable Automatic Folder Type Discovery

"Folder discovery is a feature that customizes the view settings of folders based on their content. For example, a folder with images might display thumbnails, while a folder with documents might show a list view. While this can be useful, it can also be frustrating if you prefer a uniform view for all folders."

Removing the `Bags` & `BagMRU` key resets all folder settings (view, size,...), `NotSpecified` sets the template to `General Items`. The other templates would be `Documents`, `Music`, `Videos` (folder: `Properties > Customize > Optimize this folder for:`)

The revert may not work correctly yet, as it only creates the `Bags`/`BagsMRU` keys.

# Hide Language Bar

![](https://github.com/nohuto/win-config/blob/main/visibility/images/languagebar.png?raw=true)

## Text Services and Input Languages Captures

`Time & language > Typing > Advanced keyboard settings > Language bar options`:
```c
// Floating On Desktop
RegSetValue	HKCU\Software\Microsoft\CTF\LangBar\ShowStatus	Type: REG_DWORD, Length: 4, Data: 0

// Hidden
RegSetValue	HKCU\Software\Microsoft\CTF\LangBar\ShowStatus	Type: REG_DWORD, Length: 4, Data: 3

// Docked in the taskbar
RegSetValue	HKCU\Software\Microsoft\CTF\LangBar\ShowStatus	Type: REG_DWORD, Length: 4, Data: 4
```

`Show the Language bar as transparent when inactive`:
```c
// Enabled
RegSetValue	HKCU\Software\Microsoft\CTF\LangBar\Transparency	Type: REG_DWORD, Length: 4, Data: 64

// Disabled
RegSetValue	HKCU\Software\Microsoft\CTF\LangBar\Transparency	Type: REG_DWORD, Length: 4, Data: 255
```

`Show additional Language bar icons in the taskbar`:
```c
// Enabled
RegSetValue	HKCU\Software\Microsoft\CTF\LangBar\ExtraIconsOnMinimized	Type: REG_DWORD, Length: 4, Data: 1

// Disabled
RegSetValue	HKCU\Software\Microsoft\CTF\LangBar\ExtraIconsOnMinimized	Type: REG_DWORD, Length: 4, Data: 0
```

`Show text labels on the Language bar`:
```c
// Enabled
RegSetValue	HKCU\Software\Microsoft\CTF\LangBar\Label	Type: REG_DWORD, Length: 4, Data: 1

// Disabled
RegSetValue	HKCU\Software\Microsoft\CTF\LangBar\Label	Type: REG_DWORD, Length: 4, Data: 0
```

# Hide Shortcut Icon

Removes the `- Shortcut` text, hides the shortcut & compression arrows. Works by replacing the shortcut `.ico` with a [blank image](https://github.com/nohuto/Files/releases/download/miscellaneous/Blank.ico).

### Before

![](https://github.com/nohuto/win-config/blob/main/visibility/images/shortcutbefore.png?raw=true)

### After

![](https://github.com/nohuto/win-config/blob/main/visibility/images/shortcutafter.png?raw=true)

# 'New' Context Menu

Instead of creating a `.txt` file, then renaming it to e.g. `.bat` / `.ps1`, you can add these options to the 'new' context menu. This may also change the `Type` shown in the explorer (only `.bat` is affected of the three).

`Remove 'Add to Favorites' Option`, `Remove 'Share' Option`, `Remove 'Send to' Option`, `Remove 'bmp'/'zip' Options` don't have a revert yet.

![](https://github.com/nohuto/win-config/blob/main/visibility/images/newcontext1.png?raw=true)
![](https://github.com/nohuto/win-config/blob/main/visibility/images/newcontext2.png?raw=true)

# Desktop Icon Spacing

Location:
```
\Registry\User\S-ID\Control Panel\Desktop\WindowMetrics : IconSpacing
\Registry\User\S-ID\Control Panel\Desktop\WindowMetrics : IconVerticalSpacing
```
`IconSpacing` = Horizontal
`IconVerticalSpacing` = Vertical

Default: `75px` (`-1125`)
Min: `32px` (`-480`)
Max: `182px` (`-2730`)

Value gets calculated with:
```c
-15*px

-15*75 = -1125 // default
```

I created a small tool for fun, since it's a lot easier to quickly change and test the different icon spacing. You've to log out after applying, otherwise it won't update instantly (the images show vertical `75px` & `100px` difference). I personally use `110px Horizonzal - 60px Vertical` for a more vertical compact view and more space horizontally (see suboption).

### `75px` Example

![](https://github.com/nohuto/win-config/blob/main/visibility/images/iconspacing75.png?raw=true)

### `100px`

![](https://github.com/nohuto/win-config/blob/main/visibility/images/iconspacing100.png?raw=true)

---

Desktop icon size notes:
```c
"HKCU\\Software\\Microsoft\\Windows\\Shell\\Bags\\1\\Desktop";
  "IconSize" = 32 // 32 = Small, 48 = Medium, 96 = Large
```

# Detailed File Transfer

When you copy, move, or delete a file or folder, a progress dialog appears. You can switch between `More details` and `Fewer details`. By default, the dialog opens in the same view you last used (if you didn't switch it yet, `0` is used).

### EnthusiastMode Disabled

![](https://github.com/nohuto/win-config/blob/main/visibility/images/filetransfer0.png?raw=true)

### EnthusiastMode Enabled

![](https://github.com/nohuto/win-config/blob/main/visibility/images/filetransfer1.png?raw=true)

# Alt-Tab App Tabs

Select the amount of recent tabs from apps in the alt+tab menu.

### Don't show tabs

![](https://github.com/nohuto/win-config/blob/main/visibility/images/0tabs.png?raw=true)

### 3 Tabs

![](https://github.com/nohuto/win-config/blob/main/visibility/images/3tabs.png?raw=true)

### 5 Tabs

![](https://github.com/nohuto/win-config/blob/main/visibility/images/5tabs.png?raw=true)

### 20 Tabs

![](https://github.com/nohuto/win-config/blob/main/visibility/images/20tabs.png?raw=true)

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Configure the inclusion of app tabs into Alt-Tab](https://www.noverse.dev/policies.html?p=Multitasking*BrowserAltTabBlowout) | `HKCU\Software\Policies\Microsoft\Windows\Explorer` | `MultiTaskingAltTabFilter` |

The option changes it via `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced`.

## Classic Task Switcher

Restarting the explorer is enough to apply the changes.

### New

![](https://github.com/nohuto/win-config/blob/main/visibility/images/taskswitchnew.png?raw=true)

### Classic

![](https://github.com/nohuto/win-config/blob/main/visibility/images/taskswitchold.png?raw=true)

# Disable Snap Flyout

Hides the snap assist flyout that would appear after hovering over the maximize/restore down icon:

![](https://github.com/nohuto/win-config/blob/main/visibility/images/snapflyout.png?raw=true)

# Remove Home & Gallery

### Home / Galery

![](https://github.com/nohuto/win-config/blob/main/visibility/images/homegal.png?raw=true)

### Network Sharing Folder (Suboption)

![](https://github.com/nohuto/win-config/blob/main/visibility/images/homenet.png?raw=true)

### Miscellaneous Notes

```c
{018D5C66-4533-4307-9B53-224DE2ED1FE6} = OneDrive
{F02C1A0D-BE21-4350-88B0-7367FC96EF3C} = Network Sharing Folder
{031E4825-7B94-4dc3-B131-E946B44C8DD5} = Libraries Folder
```
```json
// LaunchTo:
// 1 = This PC
// 2 = Home (default)
// 3 = Downloads
// 4 = OneDrive
"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced": {
  "LaunchTo": { "Type": "REG_DWORD", "Data": 1 }
},
"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer": {
  "HubMode": { "Type": "REG_DWORD", "Data": 1 }
}
```

# Remove Quick Access

Removes the `Quick access` in the File Explorer & sets `Open File Exporer to` to `This PC`.

![](https://github.com/nohuto/win-config/blob/main/visibility/images/quickaccess.png?raw=true)

# Hide Lock Screen

Disables the lock screen (skips the lock screen and go directly to the login screen). See content below for details on the suboptions.

Add a custom text to the sign in screen via:
```c
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
// legalnoticecaption -	Type: REG_SZ - Data: Noverse
// legalnoticetext	- Type: REG_SZ - Data: https://nohuto.github.io
```
By adding them, you'll have to click `OK` every time you boot/log in:

![](https://github.com/nohuto/win-config/blob/main/visibility/images/legalnotice.png?raw=true)

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Do not display the lock screen](https://www.noverse.dev/policies.html?p=ControlPanelDisplay*CPL_Personalization_NoLockScreen) | `HKLM\Software\Policies\Microsoft\Windows\Personalization` | `NoLockScreen` |
| [Prevent changing lock screen and logon image](https://www.noverse.dev/policies.html?p=ControlPanelDisplay*CPL_Personalization_NoChangingLockScreen) | `HKLM\Software\Policies\Microsoft\Windows\Personalization` | `NoChangingLockScreen` |
| [Prevent lock screen background motion](https://www.noverse.dev/policies.html?p=ControlPanelDisplay*CPL_Personalization_AnimateLockScreenBackground) | `HKLM\Software\Policies\Microsoft\Windows\Personalization` | `AnimateLockScreenBackground` |
| [Prevent enabling lock screen slide show](https://www.noverse.dev/policies.html?p=ControlPanelDisplay*CPL_Personalization_NoLockScreenSlideshow) | `HKLM\Software\Policies\Microsoft\Windows\Personalization` | `NoLockScreenSlideshow` |
| [Prevent enabling lock screen camera](https://www.noverse.dev/policies.html?p=ControlPanelDisplay*CPL_Personalization_NoLockScreenCamera) | `HKLM\Software\Policies\Microsoft\Windows\Personalization` | `NoLockScreenCamera` |
| [Force a specific default lock screen and logon image](https://www.noverse.dev/policies.html?p=ControlPanelDisplay*CPL_Personalization_ForceDefaultLockScreen) | `HKLM\Software\Policies\Microsoft\Windows\Personalization` | `LockScreenImage`<br>`LockScreenOverlaysDisabled` |
| [Show clear logon background](https://www.noverse.dev/policies.html?p=Logon*DisableAcrylicBackgroundOnLogon) | `HKLM\Software\Policies\Microsoft\Windows\System` | `DisableAcrylicBackgroundOnLogon` |

## Accounts Captures

`Accounts > Sign-in options` - `Automatically save my restartable apps and restart them when I sign back in`:
```c
// Off
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\RestartApps    Type: REG_DWORD, Length: 4, Data: 0

// On
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\RestartApps    Type: REG_DWORD, Length: 4, Data: 1
```

`Accounts > Sign-in options` - `Show account details such as my email address on the sign-in screen`:
```c
// On
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SystemProtectedUserData\S-{ID}\AnyoneRead\Logon\ShowEmail	Type: REG_DWORD, Length: 4, Data: 1

// Off
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SystemProtectedUserData\S-{ID}\AnyoneRead\Logon\ShowEmail	Type: REG_DWORD, Length: 4, Data: 0
```

## Personalization Captures

`Personalization > Lock screen` - `Personalize your lock screen`:
```c
// Windows spotlight
HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\RotatingLockScreenEnabled	Type: REG_DWORD, Length: 4, Data: 1
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Creative\S-{ID}\RotatingLockScreenEnabled	Type: REG_DWORD, Length: 4, Data: 1
HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\338387\SubscriptionContext	Type: REG_SZ, Length: 20, Data: sc-mode=0
HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen\SlideshowEnabled	Type: REG_DWORD, Length: 4, Data: 0
HKCU\Control Panel\Desktop\LockScreenAutoLockActive	Type: REG_SZ, Length: 4, Data: 0

// Picture
HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\RotatingLockScreenEnabled	Type: REG_DWORD, Length: 4, Data: 0
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Creative\S-{ID}\RotatingLockScreenEnabled	Type: REG_DWORD, Length: 4, Data: 0
HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\338387\SubscriptionContext	Type: REG_SZ, Length: 20, Data: sc-mode=1
HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen\SlideshowEnabled	Type: REG_DWORD, Length: 4, Data: 0
HKCU\Control Panel\Desktop\LockScreenAutoLockActive	Type: REG_SZ, Length: 4, Data: 0
HKCU\Control Panel\Desktop\DelayLockInterval // deletevalue

// Slideshow
HKCU\Control Panel\Desktop\SCRNSAVE.EXE	// deletevalue
HKCU\Control Panel\Desktop\LockScreenAutoLockActive	Type: REG_SZ, Length: 4, Data: 1
HKCU\Control Panel\Desktop\DelayLockInterval	Type: REG_DWORD, Length: 4, Data: 0
HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen\SlideshowEnabled	Type: REG_DWORD, Length: 4, Data: 1
// Include camera roll folders from this PC and OneDrive (Slideshow only)
// Enabled
HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen\SlideshowIncludeCameraRoll	Type: REG_DWORD, Length: 4, Data: 1
// Disabled
HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen\SlideshowIncludeCameraRoll	Type: REG_DWORD, Length: 4, Data: 0
// Only use pictures that fit my screen
// Enabled
HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen\SlideshowOptimizePhotoSelection	Type: REG_DWORD, Length: 4, Data: 1
// Disabled
HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen\SlideshowOptimizePhotoSelection	Type: REG_DWORD, Length: 4, Data: 0
// When my PC is inactive, show the lock screen instead of turning off the screen
// Enabled
HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen\SlideshowAutoLock	Type: REG_DWORD, Length: 4, Data: 1
HKCU\Control Panel\Desktop\LockScreenAutoLockActive	Type: REG_SZ, Length: 4, Data: 1
// Disabled
HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen\SlideshowAutoLock	Type: REG_DWORD, Length: 4, Data: 0
HKCU\Control Panel\Desktop\LockScreenAutoLockActive	Type: REG_SZ, Length: 4, Data: 0
// Turn off the screen after the slidshow has played for
// Don't turn off
HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen\SlideshowDuration	Type: REG_DWORD, Length: 4, Data: 0
// 3H
HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen\SlideshowDuration	Type: REG_DWORD, Length: 4, Data: 10800000
// 1H
HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen\SlideshowDuration	Type: REG_DWORD, Length: 4, Data: 3600000
// 30min
HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen\SlideshowDuration	Type: REG_DWORD, Length: 4, Data: 1800000

// Get fun facts, tips, tricks, and more on your lock screen (for Picture/Slideshow)
// Enabled
HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\RotatingLockScreenOverlayEnabled	Type: REG_DWORD, Length: 4, Data: 0
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Creative\S-{ID}\RotatingLockScreenOverlayEnabled	Type: REG_DWORD, Length: 4, Data: 0
HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SubscribedContent-338387Enabled	Type: REG_DWORD, Length: 4, Data: 0
// Disabled
HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\RotatingLockScreenOverlayEnabled	Type: REG_DWORD, Length: 4, Data: 1
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Creative\S-{ID}\RotatingLockScreenOverlayEnabled	Type: REG_DWORD, Length: 4, Data: 1
HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SubscribedContent-338387Enabled	Type: REG_DWORD, Length: 4, Data: 1
HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\338387\SubscriptionContext	Type: REG_SZ, Length: 20, Data: sc-mode=1
```

# Hide Most Used Apps

![](https://github.com/nohuto/win-config/blob/main/visibility/images/mostused.jpg?raw=true)

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Show or hide "Most used" list from Start menu](https://www.noverse.dev/policies.html?p=StartMenu*ShowOrHideMostUsedApps) | `HKLM\Software\Policies\Microsoft\Windows\Explorer`<br>`HKCU\Software\Policies\Microsoft\Windows\Explorer` | `ShowOrHideMostUsedApps` |
| [Remove frequent programs list from the Start Menu](https://www.noverse.dev/policies.html?p=StartMenu*NoFrequentUsedPrograms) | `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`<br>`HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` | `NoStartMenuMFUprogramsList` |
| [Turn off user tracking](https://www.noverse.dev/policies.html?p=StartMenu*NoInstrumentation) | `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` | `NoInstrumentation` |
| [Remove "Recently added" list from Start Menu](https://www.noverse.dev/policies.html?p=StartMenu*HideRecentlyAddedApps) | `HKLM\Software\Policies\Microsoft\Windows\Explorer`<br>`HKCU\Software\Policies\Microsoft\Windows\Explorer` | `HideRecentlyAddedApps` |
| [Do not show the 'new application installed' notification](https://www.noverse.dev/policies.html?p=WindowsExplorer*NoNewAppAlert) | `HKLM\Software\Policies\Microsoft\Windows\Explorer` | `NoNewAppAlert` |

# Disable Spotlight

Spotlight is used to provide new pictures on your lock screen.

These exist by default on 25H2:
```json
"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\DesktopSpotlight\\Settings": {
  "IsDisabledByCommercialControl": { "Type": "REG_DWORD", "Data": 0 },
  "IsRestoreLogon": { "Type": "REG_DWORD", "Data": 0 },
  "OneTimeUpgrade": { "Type": "REG_DWORD", "Data": 0 },
  "PeriodicUpgrade": { "Type": "REG_QWORD", "Data": 134118152903943918 },
  "SpotlightDisabledReason": { "Type": "REG_DWORD", "Data": 100 },
  "SpotlightNotOnboardedReason": { "Type": "REG_DWORD", "Data": 4 }
}
```
Disabling it via policies etc. is enough, therefore I won't add them as there's no documentation on them either.

`EnabledState` gets read.
```
\Registry\User\S-<ID>\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\DesktopSpotlight\Settings : EnabledState
```

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Configure Windows spotlight on lock screen](https://www.noverse.dev/policies.html?p=CloudContent*ConfigureWindowsSpotlight) | `HKCU\Software\Policies\Microsoft\Windows\CloudContent` | `ConfigureWindowsSpotlight`<br>`IncludeEnterpriseSpotlight` |
| [Turn off all Windows spotlight features](https://www.noverse.dev/policies.html?p=CloudContent*DisableWindowsSpotlightFeatures) | `HKCU\Software\Policies\Microsoft\Windows\CloudContent` | `DisableWindowsSpotlightFeatures` |
| [Turn off Spotlight collection on Desktop](https://www.noverse.dev/policies.html?p=CloudContent*DisableSpotlightCollectionOnDesktop) | `HKCU\Software\Policies\Microsoft\Windows\CloudContent` | `DisableSpotlightCollectionOnDesktop` |
| [Do not suggest third-party content in Windows spotlight](https://www.noverse.dev/policies.html?p=CloudContent*DisableThirdPartySuggestions) | `HKCU\Software\Policies\Microsoft\Windows\CloudContent` | `DisableThirdPartySuggestions` |
| [Turn off Windows Spotlight on Action Center](https://www.noverse.dev/policies.html?p=CloudContent*DisableWindowsSpotlightOnActionCenter) | `HKCU\Software\Policies\Microsoft\Windows\CloudContent` | `DisableWindowsSpotlightOnActionCenter` |
| [Turn off Windows Spotlight on Settings](https://www.noverse.dev/policies.html?p=CloudContent*DisableWindowsSpotlightOnSettings) | `HKCU\Software\Policies\Microsoft\Windows\CloudContent` | `DisableWindowsSpotlightOnSettings` |
| [Turn off the Windows Welcome Experience](https://www.noverse.dev/policies.html?p=CloudContent*DisableWindowsSpotlightWindowsWelcomeExperience) | `HKCU\Software\Policies\Microsoft\Windows\CloudContent` | `DisableWindowsSpotlightWindowsWelcomeExperience` |

# PowerShell Colors

Since `powershell.exe` has default color of white (foreground) and blue (background), some may want to change it. If you use Windows Terminal, this option will have no effect.

`ScreenColors` value, located in `HKCU\Console\%WINDIR%_System32_WindowsPowerShell_v1.0_powershell.exe`  
`0-3` bit = `Foreground color`  
`4-7` bit = `Background color`

### Color Table

| Color | Binary | Decimal |
| ----- | :----: | :-----: |
| Black | `0000` | `0` |
| DarkBlue | `0001` | `1` |
| DarkGreen | `0010` | `2` |
| DarkCyan | `0011` | `3` |
| DarkRed | `0100` | `4` |
| DarkMagenta | `0101` | `5` |
| DarkYellow | `0110` | `6` |
| Gray | `0111` | `7` |
| DarkGray | `1000` | `8` |
| Blue | `1001` | `9` |
| Green | `1010` | `10` |
| Cyan | `1011` | `11` |
| Red | `1100` | `12` |
| Magenta | `1101` | `13` |
| Yellow | `1110` | `14` |
| White | `1111` | `15` |

Calculate it on your own, by using [bitmask-calc](https://github.com/nohuto/bitmask-calc) - e.g. set bit `1-3` and `7`, to get `Yellow` (foreground) and `DarkGray` (background).

## Miscellaneous Notes

If you've set a custom foreground/background color, they won't override the colors changed within the code, e.g.:
```powershell
Write-Host "Noverse"
```
-> `Noverse` will have use foreground & background color of `ScreenColors`
```powershell
Write-Host "Noverse" -ForegroundColor Blue
```
-> `Noverse` will be blue, `ScreenColors` gets skipped.
```powershell
[console]::BackgroundColor = 'Black'
```
-> If it doesn't get changed within the code, it'll use the background color set by `ScreenColor`.

The option uses `Black` (background) and `Gray` (foreground), since it is personal preference change it to whatever you want using the information above.

Add the `-NoLogo` parameter to the powershell shortcut in the start menu with the command below. It hides the startup banner:
```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\Nohuto>
```
```powershell
for %%L in ("%APPDATA%\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\*.lnk") do powershell -c "$s=New-Object -ComObject WScript.Shell; $lnk=$s.CreateShortcut('%%~fL'); $lnk.TargetPath='%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe'; $lnk.Arguments='-NoLogo'; $lnk.Save()"
```

# Prevent Color/Theme Changes

Prevents changing color/appearance, desktop background, desktop icons, start background, themes. It also stops themes from changing mouse pointers and desktop icons.

Use the suboptions to prevent/allow specific parts.

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Prevent changing color and appearance](https://www.noverse.dev/policies.html?p=ControlPanelDisplay*CPL_Personalization_NoColorAppearanceUI) | `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System` | `NoDispAppearancePage` |
| [Prevent changing desktop background](https://www.noverse.dev/policies.html?p=ControlPanelDisplay*CPL_Personalization_NoDesktopBackgroundUI) | `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop` | `NoChangingWallPaper` |
| [Prevent changing desktop icons](https://www.noverse.dev/policies.html?p=ControlPanelDisplay*CPL_Personalization_NoDesktopIconsUI) | `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System` | `NoDispBackgroundPage` |
| [Prevent changing lock screen and logon image](https://www.noverse.dev/policies.html?p=ControlPanelDisplay*CPL_Personalization_NoChangingLockScreen) | `HKLM\Software\Policies\Microsoft\Windows\Personalization` | `NoChangingLockScreen` |
| [Prevent changing mouse pointers](https://www.noverse.dev/policies.html?p=ControlPanelDisplay*CPL_Personalization_NoMousePointersUI) | `HKCU\Software\Policies\Microsoft\Windows\Personalization` | `NoChangingMousePointers` |
| [Prevent changing start menu background](https://www.noverse.dev/policies.html?p=ControlPanelDisplay*CPL_Personalization_NoChangingStartMenuBackground) | `HKLM\Software\Policies\Microsoft\Windows\Personalization` | `NoChangingStartMenuBackground` |
| [Prevent changing theme](https://www.noverse.dev/policies.html?p=ControlPanelDisplay*CPL_Personalization_DisableThemeChange) | `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` | `NoThemesTab` |

# Hide Disabled/Disconnected Devices

Hides disabled/disconnected devices in the `mmsys.cpl` window.

![](https://github.com/nohuto/win-config/blob/main/visibility/images/hidedevices.png?raw=true)

## Sound Captures

```c
// Show disabled/disconnected devices
rundll32.exe	RegSetValue	HKCU\Software\Microsoft\Multimedia\Audio\DeviceCpl\ShowHiddenDevices	Type: REG_DWORD, Length: 4, Data: 1
rundll32.exe	RegSetValue	HKCU\Software\Microsoft\Multimedia\Audio\DeviceCpl\ShowDisconnectedDevices	Type: REG_DWORD, Length: 4, Data: 1

// Hide disabled/diconnected devices
rundll32.exe	RegSetValue	HKCU\Software\Microsoft\Multimedia\Audio\DeviceCpl\ShowHiddenDevices	Type: REG_DWORD, Length: 4, Data: 0
rundll32.exe	RegSetValue	HKCU\Software\Microsoft\Multimedia\Audio\DeviceCpl\ShowDisconnectedDevices	Type: REG_DWORD, Length: 4, Data: 0
```

# Force Classic Control Panel

"This policy setting controls the default Control Panel view, whether by category or icons. If this policy setting is enabled, the Control Panel opens to the icon view. If this policy setting is disabled, the Control Panel opens to the category view."

### Icon View

![](https://github.com/nohuto/win-config/blob/main/visibility/images/panel0.png?raw=true)

### Category View

![](https://github.com/nohuto/win-config/blob/main/visibility/images/panel1.png?raw=true)

## [Windows Policies](https://www.noverse.dev/policies.html)

| Policy | Key Path | Value Name |
| --- | --- | --- |
| [Always open All Control Panel Items when opening Control Panel](https://www.noverse.dev/policies.html?p=ControlPanel*ForceClassicControlPanel) | `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` | `ForceClassicControlPanel` |

# System Clock Seconds

"Uses more power" (in relation to laptops).

![](https://github.com/nohuto/win-config/blob/main/visibility/images/clock.png?raw=true)

# OEM Information

Set your own support information in `System > About` (or `Control Panel > System and Security > System`. All values are saved in:
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation
```
You used to change the logo via:
```json
"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OEMInformation": {
  "Logo": { "Type": "REG_SZ", "Data": "path\\OEM.bmp" }
}
```
But it seems deprecated (doesn't work for me). Limitation were `120x120` pixels, `.bmp` file & `32-bit` color depth.

Edit registered owner/orga (visible in `winver`) via:
```json
"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion": {
  "RegisteredOwner": { "Type": "REG_SZ", "Data": "Nohuto" },
  "RegisteredOrganization": { "Type": "REG_SZ", "Data": "Noverse" }
}
```

Edit miscellaneous things in `winver.exe` using (`basebrd.dll`/`basebrd.dll.mui`) [resourcehacker](https://www.angusj.com/resourcehacker/).

### Example

```json
"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OEMInformation": {
  "Manufacturer": { "Type": "REG_SZ", "Data": "Noverse" },
  "Model": { "Type": "REG_SZ", "Data": "Windows 11" },
  "SupportHours": { "Type": "REG_SZ", "Data": "24H" },
  "SupportPhone": { "Type": "REG_SZ", "Data": "noverse@gmail.com" },
  "SupportURL": { "Type": "REG_SZ", "Data": "https://discord.gg/noverse" }
}
```

![](https://github.com/nohuto/win-config/blob/main/visibility/images/oem.png?raw=true)

# Settings Page Visibility

It controls which pages in the windows settings app are visible (blocked pages are removed from view and direct access redirects to the main settings page).

```
This policy allows an administrator to block a given set of pages from the System Settings app. Blocked pages will not be visible in the app, and if all pages in a category are blocked the category will be hidden as well. Direct navigation to a blocked page via URI, context menu in Explorer or other means will result in the front page of Settings being shown instead.
```
Path (`String Value`):
```
HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer : SettingsPageVisibility
```
`showonly:` followed by a semicolon separated list of page identifiers to allow
`hide:` followed by a list of pages to block

Page identifiers are the part after `ms-settings:` in a settings URI.

### Example:

`showonly:bluetooth` only shows the `Bluetooth` page
`hide:bluetooth;windowsdefender` hides the `Bluetooth` & `Windows Security` pages

See a list of all categories of `ms-settings` URIs [here](https://learn.microsoft.com/en-us/windows/apps/develop/launch/launch-settings-app#ms-settings-uri-scheme-reference).

### Example Value

```bat
hide:sync;signinoptions-launchfaceenrollment;signinoptions-launchfingerprintenrollment;maps;maps-downloadmaps;mobile-devices;family-group;deviceusage;findmydevice
```

It depends on the user what he wants to see and what not, so I won't add a switch for it.
