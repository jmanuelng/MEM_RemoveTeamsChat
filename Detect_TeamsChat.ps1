<#
.SYNOPSIS
Detects presence of Microsoft Teams on a Windows device.

.DESCRIPTION
Script searches for Microsoft Teams by checking both installed and provisioned app packages for all users.

.OUTPUTS
To be used as a detection script in Microsoft Intune "Remediations".
 Outputs whether Microsoft Teams Chat is found or not.

.NOTES
Original script and concept by Andrew Taylor.
- For further information and related scripts, visit: https://andrewstaylor.com/2023/02/10/removing-teams-chat-from-windows-11-via-powershell-and-intune/
- Original script source: https://github.com/andrew-s-taylor/public/tree/main/Powershell%20Scripts/Intune/Teams-Chat

#>

#region Initialize

# Define the application name to search for
$MSTeams = "MicrosoftTeams"

# Initialize a detection counter to track the presence of Teams
$detection = 0

#endregion Initialize

# Search for Teams as an installed package for all users
$WinPackage = Get-AppxPackage -allusers | Where-Object {$_.Name -eq $MSTeams}

# Search for Teams as a provisioned package in the system
$ProvisionedPackage = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $MSTeams }


# Check for the presence of Microsoft Teams as an installed package for any user.
# An installed package indicates that the application has been installed and is available for use by at least one user on the system.
# Incrementing the counter creates non-zero result, an error, a detection, means the fix or remediation should be executed
if ($null -ne $WinPackage) {
    $detection++
}

# Check for the presence of Microsoft Teams as a provisioned package in the Windows image.
# A provisioned package is not immediately available for use but is included in the system's image for automatic installation for new users.
# Detecting a provisioned package means Microsoft Teams is set to be available for any new user profiles created on the system,
# Incrementing the counter creates non-zero result, an error, a detection, means the fix or remediation should be executed
if ($null -ne $ProvisionedPackage) {
    $detection++
}

# Evaluate the detection counter to determine compliance
if ($detection -eq 0) {
    Write-Host "OK $([datetime]::Now) : Teams Chat not found."
    exit 0
} else {
    Write-Host "FAIL $([datetime]::Now) : Teams Chat was found, fix."
    exit 1
}

# Note: The script exits with 0 for compliance (Teams not found) and exits with 1 for non-compliance (Teams found).
# This behavior is useful for integrating the script into automated compliance checks and systems management tools.
