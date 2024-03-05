# Enable Script Execution
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser

# Disable Script Execution
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser

# TODO @phish documentation

function Wait-AnyKey {
  param(
    [string]
    $Message = "Press any key to continue"
  )
  if ($psISE)
  {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show("$Message")
  }
  else
  {
    Write-Host "$Message" -ForegroundColor Yellow
    $Unused = $host.ui.RawUI.ReadKey("NoEcho,IncludeKeyDown")
  }
}

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
  rm  -Force c:\secpol.cfg -confirm:$false
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
}

# Disabled UAC Prompt
function Unprotect-UAC {
  reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
}

function New-LocalAdmin {
  # TODO phish TESTING!
  [CmdletBinding()]
  param (
    [string]
    $UserName = "ITadmin"

    [Parameter(
      ValidateSet(
        "Administrators", 
        "Users", 
        ErrorMessage="Edit the script for that particular group if it's needed"
      )
    )]
    [string]
    $GroupName = "Administrators"

    [string]
    $Description = "42 North Dental Local Admin Account"
  )
  
  $User = "$env:COMPUTERNAME\$UserName"
  $UserExists = (Get-LocalUser).Name -Contains $User
  $Group = $GroupName
  $InGroup = (Get-LocalGroupMember $Group).Name -contains $User

  # Password
  do {
    $Password = Read-Host -AsSecureString -Prompt "$User PASSWORD(1): "
    $Verified = Read-Host -AsSecureString -Prompt "$User PASSWORD(2): "
    $Secret1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
    $Secret2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
  } while ($Secret1 -ne $Secret2)
  
  if ($UserExists -ne $true) {
    Write-Verbose "Creating new user $User"
    New-LocalUser -Name $User -Description $Description -Password $Password -PasswordNeverExpires
  } else {
    Write-Verbose "Setting user $User password, flags, and description"
    Set-LocalUser -Name $User -Description $Description -Password $Password -PasswordNeverExpires
  }
  if ($InGroup -ne $true) {
    Write-Verbose "Adding user $User to group: $Group"
    Add-LocalGroupMember -Group $Group -Member $User
  }
  if ($Group -ne "Administrators") {
    Write-Verbose "Prevent user from changing password"
    Set-LocalUser -Name $User -UserMayChangePassword $false
  }
}

function Unprotect-FileAndPrinter {
  # Enable File and Printer Sharing (30 rules)
  netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
}

function Rename-Host {
  # Saving variable for later
  $Hostname = $env:HOSTNAME
  
  # Confirm Hostname
  while ($Confirmation -like "y*" -Or $Confirmation -like "n*") {
    $Confirmation = Read-Host -Prompt "Is $Hostname the correct hostname? (Y/n)"
  }
  if ($Confirmation -like "n*") {
    $Hostname = Read-Host -Prompt "New Hostname"
    Rename-Computer -NewName $Hostname
  }
}

function Disable-DefaultAdmin {
  Disable-LocalUser -Name "Administrator"
}
