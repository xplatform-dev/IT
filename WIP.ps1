# Enable Script Execution
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser

# Disable Script Execution
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser

# Removes password lenth requirements
secedit /export /cfg C:\secpol.cfg
(Get-Content C:\secpol.cfg) -Replace "PasswordLength = [0-9]*", "PasswordLength = 0" | Out-File C:\secpol.cfg
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpol.cfg /areas SECURITYPOLICY
rm  -Force c:\secpol.cfg -confirm:$false

# Activates Windows
$ProductKey = (Get-CimInstance -ClassName SoftwareLicensingService).OA3xOriginalProductKey
if ($null -ne $ProductKey) {
Start-Process -FilePath C:\Windows\System32\changepk.exe -ArgumentList "/ProductKey $ProductKey"
} else {
Write-Host "Product Key not found"
}

# Disabled UAC Prompt
reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f

# Create Local Administrator "ITadmin"
$User = "ITadmin"
$Group = "Administrators"
do {
  $Password = Read-Host -AsSecureString -Prompt "$User PASSWORD(1): "
  $Verified = Read-Host -AsSecureString -Prompt "$User PASSWORD(2): "
  $Secret1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
  $Secret2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
} while ($Secret1 -ne $Secret2)
New-LocalUser -Name $User -Description "42 North Dental Local Admin Account" -Password $Password -PasswordNeverExpires
Add-LocalGroupMember -Group $Group -Member $User

# Enable File and Printer Sharing (30 rules)
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes

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

# Create Local User
$User = $Hostname.split('-')[1]
$Group = "Users"
do {
  $Password = Read-Host -AsSecureString -Prompt "$User PASSWORD(1): "
  $Verified = Read-Host -AsSecureString -Prompt "$User PASSWORD(2): "
  $Secret1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
  $Secret2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
} while ($Secret1 -ne $Secret2)
New-LocalUser -Name $User -Description "42 North Dental Local Admin Account" -Password $Password -PasswordNeverExpires
Add-LocalGroupMember -Group $Group -Member $User

# Disable local default Administrator account
Disable-LocalUser -Name "Administrator"
