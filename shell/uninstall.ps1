# Uninstall registry keys and remove files

# Require admin rights (preserve working directory)

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-c cd '$pwd'; & '$PSCommandPath'"
    exit
}

# Warn user: this will delete CU directory!

Add-Type -AssemblyName PresentationFramework
$dialogResult = [System.Windows.MessageBox]::Show("This will delete the C:\Program Files\CU directory. Continue?", "Uninstall", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)

if ($dialogResult -ne [System.Windows.MessageBoxResult]::Yes) {
    exit
}

# Uninstall registry keys and remove files

$cuDir = "C:\Program Files\CU"
if (Test-Path "$cuDir\reg") {
    # Uninstall registry keys
    Start-Process regedit.exe -ArgumentList "`"$cuDir\reg\uninstall.reg`"" -Wait
    Remove-Item -Recurse -Force "$cuDir"
}

# MessageBox (powershell command)

Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show("zCU shell extension Uninstalled", "Uninstall", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)

