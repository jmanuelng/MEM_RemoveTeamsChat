<#
.SYNOPSIS
Script removes Microsoft Teams Chat from Windows devices, including uninstalling the app for all users, removing provisioned packages, and applying registry tweaks to prevent its reinstallation and unpin it from the taskbar.

.DESCRIPTION
Intended to be executes as Fix for "Remediations" in Microsoft Intune
IT automates removing Microsoft Teams Chat from Windows devices.
Addresses application at both the installed and system provisioned to make sure it is removed for current users and is not automatically installed for new users. 
It also modifies Registry settings to prevent automatic reinstallation of Teams Chat and to unpins it from the taskbar.

.OUTPUTS
String. Outputs a message indicating that Teams Chat has been removed.

.NOTES

For more information and original scripts by Andrew Taylor, visit:
- Blog post: https://andrewstaylor.com/2023/02/10/removing-teams-chat-from-windows-11-via-powershell-and-intune/
- GitHub repository: https://github.com/andrew-s-taylor/public/blob/main/Powershell%20Scripts/Intune/Teams-Chat/remediate-teams-chat.ps1
#>

# Define the application identifier for Microsoft Teams Chat
$MSTeams = "MicrosoftTeams"

# Retrieve Microsoft Teams Chat package information for all users
$WinPackage = Get-AppxPackage -allusers | Where-Object {$_.Name -eq $MSTeams}

# Retrieve the provisioned Microsoft Teams Chat package from the Windows image
# Unlike the installed package, the provisioned package refers to the app's inclusion in the system's image, allowing it to be automatically installed for new user accounts. Removing this package prevents automatic installation for future users.
$ProvisionedPackage = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $MSTeams }

# If the installed package is found, remove it for all users
If ($null -ne $WinPackage) {
    Remove-AppxPackage -Package $WinPackage.PackageFullName -AllUsers
    # This command uninstalls the app package from all user accounts on the machine
}

# If the provisioned package is found, remove it
If ($null -ne $ProvisionedPackage) {
    Remove-AppxProvisionedPackage -online -Packagename $ProvisionedPackage.Packagename -AllUsers
    # This command removes the provisioned package, preventing its automatic installation for new users
}

# Modify registry permissions to enable further configurations
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications"
$acl = Get-Acl -Path $registryPath
$acl.SetOwner([System.Security.Principal.NTAccount]"Administrators")
Set-Acl -Path $registryPath -AclObject $acl
# This section adjusts the ownership of the registry path, allowing administrators to make changes

# Ensure the Communications registry key exists and disable Teams Chat auto-installation
If (!(Test-Path $registryPath)) { 
    New-Item $registryPath
}
Set-ItemProperty $registryPath ConfigureChatAutoInstall -Value 0
# This disables the auto-installation feature for Teams Chat, ensuring it does not get reinstalled automatically

# Ensure the policy for Windows Chat is in place and unpin Teams Chat from the taskbar
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat"
If (!(Test-Path $registryPath)) { 
    New-Item $registryPath
}
Set-ItemProperty $registryPath "ChatIcon" -Value 2
# This action unpin Teams Chat icon from the taskbar, cleaning up the user interface

# Final message indicating successful removal
write-host "Removed Teams Chat"
# Notifies the user of the script's completion and the successful removal of Teams Chat
