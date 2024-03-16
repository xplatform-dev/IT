# TODO phish@xplatform.dev documentation
# Removes password lenth requirements
function Unprotect-LocalPasswordLimit {
  [CmdletBinding()]
  $database = "C:\secpol.cfg"
  Write-Verbose "Writing security policies to $database from $env:HOSTNAME"
  secedit /export /cfg $database
  Write-Verbose "Editing security policies at $database"
  (Get-Content $database) -Replace "PasswordLength = [0-9]*", "PasswordLength = 0" | Out-File C:\secpol.cfg
  Write-Verbose "Reading security policies from $database to $env:HOSTNAME"
  secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpol.cfg /areas SECURITYPOLICY
  Write-Verbose "Deleting file $database"
  Remove-Item  -Force  -Path "c:\secpol.cfg" -confirm:$false
}

# Activates Windows
function Enable-Windows {
  [CmdletBinding()]
  $ProductKey = (Get-CimInstance -ClassName SoftwareLicensingService).OA3xOriginalProductKey
  if ($null -ne $ProductKey) {
    Write-Verbose "Activating Windows with key $ProductKey"
    Start-Process -FilePath C:\Windows\System32\changepk.exe -ArgumentList "/ProductKey $ProductKey"
  } else {
    Write-Host "Product Key not found"
  }
  Remove-Item -Force -Path "C:\Users\Public\Desktop\Microsoft Edge.lnk"
}

# Disabled UAC Prompt
function Disable-UAC {
  reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
}

function New-LocalAccount {
  # TODO phish@xplatform.dev TESTING!
  [CmdletBinding()]
  param (
    [Parameter(Mandatory=$true)]
    [string]$UserName,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Users", "Administrators"
      <# PowerShell 7 Feature, ErrorMessage="Probably need to edit the script for that group" #>)]$GroupName,

    [Parameter(Mandatory=$false)]
    [string]$Description,

    [Parameter(Mandatory=$false)]
    [string]$FullName,

    [switch]$PasswordExpires,

    [switch]$ForbidChangePassword
  )
  
  $QualifiedUser = "$env:COMPUTERNAME\$UserName"
  $UserExists = Get-LocalUser -Name $UserName 2> $null

  # Password
  do {
    $Password = Read-Host -AsSecureString -Prompt "$QualifiedUser PASSWORD(1): "
    $Verified = Read-Host -AsSecureString -Prompt "$QualifiedUser PASSWORD(2): "
    $Secret1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
    $Secret2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Verified))
  } while ($Secret1 -ne $Secret2)
  
  # Account
  if (!($UserExists)) {
    New-LocalUser -Description $Description -FullName $FullName -Name $UserName -Password $Password -PasswordNeverExpires
  } else {
    Set-LocalUser -Description $Description -FullName $FullName -Name $UserName -Password $Password -PasswordNeverExpires $true
  }
  if ($PasswordExpires) {Set-LocalUser -Name $UserName -PasswordNeverExpires $false}
  if ($ForbidChangePassword) {
    Set-LocalUser -Name $UserName -UserMayChangePassword $false
  } else {
    Set-LocalUser -Name $UserName -UserMayChangePassword $true
  }
  
  $InGroup = Get-LocalGroupMember -Group $GroupName -Member $UserName 2> $null
  if (!($InGroup)) {
    Add-LocalGroupMember -Group $GroupName -Member $UserName -confirm:$false
  }
}

function Grant-FileAndPrinterSharing {
  # Enable File and Printer Sharing (30 rules)
  netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
}

function Grant-NetworkDiscovery {
  # Enable Network Discovery
  netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
}

function Disable-DefaultAdmin {
  Disable-LocalUser -Name "Administrator"
}

# TODO phish@xplatform.dev chrome password manager https://www.tenforums.com/tutorials/115669-enable-disable-saving-passwords-google-chrome-windows.html

function New-AcquisitionAgentTask {
  $AA_Path = "C:\Program Files (x86)\Acquisition Agent\Acquisition Agent.exe"
  
  $TaskName = "Run Acquisition Agent as Admin"
  $T = Get-ScheduledTask -TaskName $TaskName 2> $null
  if ($T) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
  }
  $Description = "Runs $AA_Path as Admin"
  $Action = New-ScheduledTaskAction -Execute $AA_Path
  $Trigger = New-ScheduledTaskTrigger -AtLogOn 
  $Principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\ITAdmin" -RunLevel Highest -LogonType "ServiceAccount"
  $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Compatibility "Win8"
  # Stopping multiple Instances is not a supported enum, but this value is. 
  # > [System.Enum]::GetNames('Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.MultipleInstancesEnum')
  $Settings.CimInstanceProperties.Item("MultipleInstances").Value = 3
  $Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Description $Description -Principal $Principal -Settings $Settings
  Register-ScheduledTask "Run Acquisition Agent as Admin" -InputObject $Task
  Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*"
}

function Initialize-Cleanup {
  <# DO NOT USE #>
  Enable-Windows
  Unprotect-LocalPasswordLimit
  Disable-UAC
  New-LocalAccount
  Grant-FileAndPrinterSharing
  Grant-NetworkDiscovery
  Disable-DefaultAdmin
}

function Initialize-PC {
  Enable-Windows
  Disable-UAC
  Unprotect-LocalPasswordLimit
  Grant-FileAndPrinterSharing
  New-AcquisitionAgentTask
  # Rename-Computer
  # Restart-Computer -Wait 
  New-LocalAccount -UserName "ITAdmin" -GroupName "Administrators" -Description "42 North Dental Local Administrator Account" -FullName "IT Admin"
  New-LocalAccount -UserName "Administrator" -GroupName "Administrators" -Description "Windows Default Admin Account" -FullName "Local Administrator"
  # Install Applications
  # Local User Account?
  # Group Policy
  Disable-DefaultAdmin
  # Restart-Computer -Wait
}

function Display-NamingConvention {
  Write-Host "Naming convention is 000-XXX#-T"
  Write-Host "\tWhere '000' = Location ID number, HQ is 000"
  Write-Host "\tWehre 'XXX' = Department shorthand:"
  Write-Host "\t\t\tFD = Front Desk,\t\t# = 1 OR 2 digit(s) for the stations"
  Write-Host "\t\t\tOP = Operatory,\t\tThe # = TWO DIGITS for the operatory room. OP04, even if the office only has 8 rooms"
  Write-Host "\t\t\tDR = Doctor or Associate,\t\t# = 1 digit for the stations"
  Write-Host "\t\t\tIT = IT Closet,\t\t# = TBD"
  Write-Host "\t\t\tLAB = Laboratory,\t\t# = TBD"
  Write-Host "\t\t\tMAN = Manager,\t\tNo number"
  Write-Host "\t\t\tDIR = Director,\t\tNo number"
  Write-Host "\t\t\tMKT = Markering,\t\t# = TBD"
  Write-Host "\t\t\tACT = Accounting,\t\t# = TBD"
  Write-Host "\t\t\tetc."
  Write-Host "\tWhere 'T' is the type shorthand:"
  Write-Host "\t\t\tD = Desktop"
  Write-Host "\t\t\tL = Laptop"
  <# We don't use these 
  Write-Host "\t\t\tT = Tablet"
  Write-Host "\t\t\tP = Phone"
  <# #>
  Write-Host "Examples:"
  Write-Host "000-IT04-L = Headquarters, IT Department, Computer #04, laptop"
  Write-Host "001-FD01-D = GD Brookline, Front Desk, Computer #01, Desktop"
}

function Rename-Host {
  $Input = $null
  do {
    Write-Host "The current computer name is $env:ComputerName, do you want to rename it?"
    $Input = Read-Host -Prompt "[Y] Yes, [N] No (Default), [I] Information, [A] Abort
  } until ($Input.ToUpper()[0] -match "YNIA")
  switch ($Input) {
    # FIXME phish@xplatform.dev Finish this.
  }
}

Initialize-PC
