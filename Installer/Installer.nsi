;NSIS Modern User Interface
;Basic Example Script
;Written by Joost Verburg

;--------------------------------
;Include Modern UI

  !include "MUI2.nsh"

;--------------------------------
;General

  ;Name and file
  Name "EID Authentication"
  OutFile "EIDInstall.exe"

  ;Default installation folder
  InstallDir "$SYSDIR"
  

  ;Request application privileges for Windows Vista
  RequestExecutionLevel admin

;--------------------------------
;Interface Settings

  !define MUI_ABORTWARNING

;--------------------------------
;Pages

  !insertmacro MUI_PAGE_LICENSE "${NSISDIR}\Docs\Modern UI\License.txt"
  !insertmacro MUI_PAGE_COMPONENTS
  !insertmacro MUI_PAGE_INSTFILES
  
  !insertmacro MUI_UNPAGE_CONFIRM
  !insertmacro MUI_UNPAGE_INSTFILES
  !insertmacro MUI_PAGE_FINISH
;--------------------------------
;Languages
 
  !insertmacro MUI_LANGUAGE "English"



;--------------------------------
;Installer Sections

Section "Core" SecCore
  SectionIn RO

  SetOutPath "$INSTDIR"
  
  ;ADD YOUR OWN FILES HERE...
  FILE "..\Release\EIDAuthenticationPackage.dll"
  FILE "..\Release\EIDCredentialProvider.dll"

 
  ;Create uninstaller
  WriteUninstaller "$INSTDIR\EIDUninstall.exe"

  ;Uninstall info
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication" "DisplayName" "EID Authentication"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication" "UninstallString" "$INSTDIR\EIDUninstall.exe"

  System::Call "EIDAuthenticationPackage::DllRegister()"
  System::Call "EIDCredentialProvider::DllRegister()"
 
 
  SetPluginUnload manual

  SetRebootFlag true

SectionEnd

;--------------------------------
;Descriptions

  ;Language strings
  LangString DESC_SecCore ${LANG_ENGLISH} "Core"

  ;Assign language strings to sections
  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} $(DESC_SecCore)
  !insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
;Uninstaller Section

Section "Uninstall"


  System::Call "EIDAuthenticationPackage::DllUnRegister()"
  System::Call "EIDCredentialProvider::DllUnRegister()"

  Delete /REBOOTOK "$INSTDIR\EIDUninstall.exe"
  Delete /REBOOTOK "$INSTDIR\EIDAuthenticationPackage.dll"
  Delete /REBOOTOK "$INSTDIR\EIDCredentialProvider.dll"

  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\EIDAuthentication"

  SetPluginUnload manual
  SetRebootFlag true

SectionEnd

