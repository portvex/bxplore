; NSIS installer for bxplore. Built by packaging/windows/build.sh, which passes
; VERSION, ARCH (x64 or arm64), EXE, ICON, OUT, TITLE, NAME, PUBLISHER.
Unicode true
!include "MUI2.nsh"
!include "x64.nsh"

Name "${TITLE} ${VERSION}"
OutFile "${OUT}"
InstallDir "$PROGRAMFILES64\${TITLE}"
InstallDirRegKey HKLM "Software\${TITLE}" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${TITLE}"
VIAddVersionKey "CompanyName" "${PUBLISHER}"
VIAddVersionKey "FileDescription" "${TITLE} installer"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "${PUBLISHER}"

!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\${NAME}.exe"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${TITLE}"

Function .onInit
  SetRegView 64
  !if "${ARCH}" == "arm64"
    ${IfNot} ${IsNativeARM64}
      MessageBox MB_ICONSTOP "This installer is for Windows on ARM64. Use the x64 installer on this computer."
      Abort
    ${EndIf}
  !else
    ${IfNot} ${RunningX64}
      MessageBox MB_ICONSTOP "This program needs 64-bit Windows."
      Abort
    ${EndIf}
  !endif
FunctionEnd

Function un.onInit
  SetRegView 64
FunctionEnd

; "Open with bxplore" on executable file types, like src/shellmenu.rs does for a
; portable copy. SystemFileAssociations applies whatever program opens the type.
!macro MenuAdd EXT
  WriteRegStr HKLM "Software\Classes\SystemFileAssociations\.${EXT}\shell\bxplore" "" "Open with ${TITLE}"
  WriteRegStr HKLM "Software\Classes\SystemFileAssociations\.${EXT}\shell\bxplore" "Icon" '"$INSTDIR\${NAME}.exe"'
  WriteRegStr HKLM "Software\Classes\SystemFileAssociations\.${EXT}\shell\bxplore\command" "" '"$INSTDIR\${NAME}.exe" "%1"'
!macroend
!macro MenuRemove EXT
  DeleteRegKey HKLM "Software\Classes\SystemFileAssociations\.${EXT}\shell\bxplore"
!macroend
!macro MenuAll ACTION
  !insertmacro ${ACTION} "exe"
  !insertmacro ${ACTION} "dll"
  !insertmacro ${ACTION} "sys"
  !insertmacro ${ACTION} "ocx"
  !insertmacro ${ACTION} "scr"
  !insertmacro ${ACTION} "cpl"
  !insertmacro ${ACTION} "drv"
  !insertmacro ${ACTION} "efi"
  !insertmacro ${ACTION} "mui"
  !insertmacro ${ACTION} "ax"
  !insertmacro ${ACTION} "tlb"
  !insertmacro ${ACTION} "so"
  !insertmacro ${ACTION} "elf"
  !insertmacro ${ACTION} "o"
  !insertmacro ${ACTION} "ko"
  !insertmacro ${ACTION} "dylib"
  !insertmacro ${ACTION} "bundle"
  !insertmacro ${ACTION} "a"
  !insertmacro ${ACTION} "lib"
!macroend

Section "${TITLE}" SecMain
  SectionIn RO
  SetShellVarContext all
  SetOutPath "$INSTDIR"
  File "/oname=${NAME}.exe" "${EXE}"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\${TITLE}" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" "${TITLE}"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\${NAME}.exe"
  WriteRegStr HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
  ; Start clean when installing over an earlier copy: the entry an earlier
  ; installer put on every file type, and the entries of an install that had
  ; the menu component ticked. SecMenu adds them again when it is selected.
  DeleteRegKey HKLM "Software\Classes\*\shell\${TITLE}"
  !insertmacro MenuAll MenuRemove
SectionEnd

Section "Start menu shortcut" SecStart
  SetShellVarContext all
  CreateShortcut "$SMPROGRAMS\${TITLE}.lnk" "$INSTDIR\${NAME}.exe"
SectionEnd

Section /o "Desktop shortcut" SecDesktop
  SetShellVarContext all
  CreateShortcut "$DESKTOP\${TITLE}.lnk" "$INSTDIR\${NAME}.exe"
SectionEnd

Section "Explorer menu: Open with ${TITLE} (executable files)" SecMenu
  !insertmacro MenuAll MenuAdd
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  Delete "$SMPROGRAMS\${TITLE}.lnk"
  Delete "$DESKTOP\${TITLE}.lnk"
  Delete "$INSTDIR\${NAME}.exe"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  !insertmacro MenuAll MenuRemove
  ; The entry an earlier installer put on every file type.
  DeleteRegKey HKLM "Software\Classes\*\shell\${TITLE}"
  DeleteRegKey HKLM "${UNINST_KEY}"
  DeleteRegKey HKLM "Software\${TITLE}"
SectionEnd
