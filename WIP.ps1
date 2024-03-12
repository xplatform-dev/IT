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
function Disable-UAC {
  reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
}

function New-LocalAccount {
  # TODO phish@xplatform.dev TESTING!
  [CmdletBinding()]
  $UserName = "ITAdmin"
  $Description = "42 North Dental Local Admin Account"
  $GroupName = "Administrators"
  
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

function Grant-FileAndPrinterSharing {
  # Enable File and Printer Sharing (30 rules)
  netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
}

function Grant-NetworkDiscovery {
  # Enable Network Discovery
  netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
}

workflow Rename-Host {
  # Saving variable for later
  $Hostname = $env:HOSTNAME
  
  # Confirm Hostname
  while ($Confirmation -like "y*" -Or $Confirmation -like "n*" -Or $Confirmation -eq "") {
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

# TODO phish@xplatform.dev chrome password manager https://www.tenforums.com/tutorials/115669-enable-disable-saving-passwords-google-chrome-windows.html

function New-AcquisitionAgentTask {  
  <#
  $action = New-ScheduledTaskAction -Execute "C:\Program Files (x86)\Acquisition Agent\Acquisition Agent.exe"
  $trigger = New-ScheduledTaskTrigger -AtLogon
  $principal = New-ScheduledTaskPrincipal -UserID "$env:HOSTNAME\Administrator" 
  $settings = New-ScheduledTaskSettingsSet -AtLogOn
  $task = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings
  Register-ScheduledTask T1 -InputObject $task
  #>
  
  $AA_Path = "C:\Program Files (x86)\Acquisition Agent\Acquisition Agent.exe"
  
  $TaskName = "Run Acquisition Agent as Admin"
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
  $Description = "Runs $AA_Path as Admin"
  $Action = New-ScheduledTaskAction -Execute $AA_Path
  $Trigger = New-ScheduledTaskTrigger -AtLogOn 
  $Principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\ITAdmin" -RunLevel Highest -LogonType "ServiceAccount"
  # TODO phish@xplatform.dev Setting mapping
  $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Compatibility "Win10"
  $Settings.CimInstanceProperties.Item("MultipleInstances").Value = 3
  # TODO phish@xplatform.dev Verify -AtLogOn for all users
  $Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Description $Description -Principal $Principal -Settings $Settings
  Register-ScheduledTask "Run Acquisition Agent as Admin" -InputObject $Task
}

function Initilize-Cleanup {
  Unprotect-LocalPasswordLimit
  Enable-Windows
  Disable-UAC
  New-LocalAccount
  Grant-FileAndPrinterSharing
  Grant-NetworkDiscovery
  Disable-DefaultAdmin
}

function Initilize-PC {
  Unprotect-LocalPasswordLimit
  Enable-Windows
  Disable-UAC
  New-LocalAccount
  Grant-FileAndPrinterSharing
  # New-AcquisitionAgentTask
  Disable-DefaultAdmin
}

# TODO phish@xplatform.dev implement this
workflow Initilize-LocalPC {
  
}

# TODO phish@xplatform.dev implement this
workflow Initilize-DomainPC {

}
