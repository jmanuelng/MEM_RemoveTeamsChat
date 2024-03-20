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

# Initialize execution summary variable. 
# Will collect brief messages of actions and errors, helps troubleshoot easily even directly form Microsoft Intune console.
$execSummary = @()

# Allows for disgnostics log. Non-zero = error at some point of execution.
$status = 0

# Define the application identifier for Microsoft Teams Chat
$MSTeams = "MicrosoftTeams"

# Retrieve Microsoft Teams Chat package information for all users.
try {
    $WinPackage = Get-AppxPackage -allusers | Where-Object {$_.Name -eq $MSTeams}
    $execSummary += "Retrieved WinPkg"
} catch {
    $execSummary += "WinPkg Error"
    $status = 1
}

# Retrieve the provisioned Microsoft Teams Chat package from the Windows image
# Unlike the installed package, the provisioned package refers to the app's inclusion in the system's image, allowing it to be automatically installed for new user accounts. Removing this package prevents automatic installation for future users.
try {
    $ProvisionedPackage = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $MSTeams }
    $execSummary += "Retrieved ProvPkg"
    $status = 0
} catch {
    $execSummary += "ProvPkg Error"
    $status = 1
}

# If the installed package is found, remove it for all users
try {
    If ($null -ne $WinPackage) {
        Remove-AppxPackage -Package $WinPackage.PackageFullName -AllUsers
        # This command uninstalls the app package from all user accounts on the machine
        $execSummary += "Removed WinPkg"
        # If it can remove app then previous errors are irrelevant. So status goes back to 0
        $status = 0
    }
} catch {
    $execSummary += "Remove WinPkg Err"
    $status = 2
}

# If the provisioned package is found, remove it
try {
    If ($null -ne $ProvisionedPackage) {
        Remove-AppxProvisionedPackage -online -Packagename $ProvisionedPackage.Packagename -AllUsers
        # This command removes the provisioned package, preventing its automatic installation for new users
        $execSummary += "Removed ProvPkg"
    }
} catch {
    $execSummary += "Rmv ProvPkg Err"
    $status = 2
}

### Modify registry permissions to enable further configurations
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications"

# Dynamically identify the name of the Administrators group regardless of the system language.
# The well-known SID for the Administrators group is consistent across Windows installations
$expectedAdminGroupName = (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate([System.Security.Principal.NTAccount]).Value

try {
    # Check current owner of the registry key
    $acl = Get-Acl -Path $registryPath
    $currentOwner = $acl.Owner


    # Compare current owner with expected Administrators group
    if ($currentOwner -ne $expectedAdminGroupName) {
        # If not matching, attempt to change the owner to Administrators group
        # Store the identified name of the Administrators group in a variable for later use.
        $adminGroup = [System.Security.Principal.NTAccount]$expectedAdminGroupName
        $acl.SetOwner($adminGroup)
        Set-Acl -Path $registryPath -AclObject $acl -ErrorAction Stop
        
        # Verify the change by checking the owner again
            # Retrieve the current Access Control List (ACL) for the registry path.
        $acl = Get-Acl -Path $registryPath # Refresh ACL info
        if ($acl.Owner -eq $expectedAdminGroupName) {
            # Verification successful
            Write-Host "Ownership correctly set to Administrators."
            $execSummary += "Ownership Set Verified"
        } else {
            # Verification failed
            Write-Host "Fail in ownership change."
            $execSummary += "Ownership Verify Fail"
            $status = 3
        }
    } else {
        # No change needed, already owned by expected Administrators group
        Write-Host "Registry key already owned by Administrators. No change needed."
        $execSummary += "Ownership OK, No Change"
    }
} catch {
    Write-Host "Error setting or verifying ACL."
    $execSummary += "ACL Error"
    $status = 3
}
### This section adjusts the ownership of the registry path, allowing administrators to make changes

# Ensure the Communications registry key exists and disable Teams Chat auto-installation
try {
    # Disable Teams Chat auto-installation
    If (!(Test-Path $registryPath)) { 
        New-Item $registryPath
    }
    Set-ItemProperty $registryPath ConfigureChatAutoInstall -Value 0 -ErrorAction Stop
    $execSummary += "Disabled AutoInstall"
} catch {
    $execSummary += "AutoInstall Error"
    $status = 4
}
# This disables the auto-installation feature for Teams Chat, ensuring it does not get reinstalled automatically

# Unpin Teams Chat from the taskbar
try {
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat"
    If (!(Test-Path $registryPath)) { 
        New-Item $registryPath
    }
    Set-ItemProperty $registryPath "ChatIcon" -Value 2 -ErrorAction Stop
    $execSummary += "Unpinned Chat"
} catch {
    $execSummary += "Unpin Error"
    $status = 5
}

# Join summary text
$execSummary = $execSummary -join ", "

# Easier to read in log file
 Write-Host "`n`n"

# Final message, notifies script's completionget and execution status.
if ($status -eq 0) {
    Write-Host "OK $([datetime]::Now) : Teams Chat removed. Summary = $execSummary."
    exit 0
} elseif ($status -eq 3 -or $status -eq 4 -or $status -eq 5) {
    Write-Host "NOTE $([datetime]::Now) : Potential issues removing Teams Chat. Status = $status. Summary = $execSummary."
    exit $status
} else {
    Write-Host "FAIL $([datetime]::Now) : Error removing Teams Chat. Status = $status. Summary = $execSummary."
    exit $status
}exit 1


#  Fin!!
