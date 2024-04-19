# Install registry keys for the shell extension

# 0. Require admin rights (preserve working directory)

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-c cd '$pwd'; & '$PSCommandPath'"
    exit
}

# 1. Make CU directory

$cuDir = "C:\Program Files\CU"
$cuDirEscaped = "C:\\Program Files\\CU"
if (!(Test-Path $cuDir\reg)) {
    New-Item -ItemType Directory -Path $cuDir
    New-Item -ItemType Directory -Path $cuDir\reg
}

# 2. Replace ${CU_PATH} in template with $cuDir

Copy-Item -Path ".\reg\shell.reg.template" -Destination ".\reg\shell.reg"
(Get-Content ".\reg\shell.reg") | ForEach-Object { $_ -replace '\$\{CU_PATH\}', $cuDirEscaped } | Set-Content ".\reg\shell.reg"

# 3. Copy files

Copy-Item -Path "..\build\lab3.exe" -Destination "$cuDir\lab3.exe"
Copy-Item -Path "..\build\zcu.exe" -Destination "$cuDir\zcu.exe"

Copy-Item -Path ".\reg\shell.reg" -Destination "$cuDir\reg\shell.reg"
Copy-Item -Path ".\reg\uninstall.reg" -Destination "$cuDir\reg\uninstall.reg"
Copy-Item -Path ".\uninstall.ps1" -Destination "$cuDir\uninstall.ps1"

# 4. Install registry keys from shell.reg

Start-Process regedit.exe -ArgumentList "`"$cuDir\reg\shell.reg`"" -Wait

# MessageBox (powershell command)

Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show("zCU shell extension Installed", "Install", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)

