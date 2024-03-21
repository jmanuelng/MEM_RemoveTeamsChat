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
Longer than original script from Andew, but does not make use of SerACL.exe, reducing potential issues downloading the application.
For more information and original scripts by Andrew Taylor, visit:
- Blog post: https://andrewstaylor.com/2023/02/10/removing-teams-chat-from-windows-11-via-powershell-and-intune/
- GitHub repository: https://github.com/andrew-s-taylor/public/blob/main/Powershell%20Scripts/Intune/Teams-Chat/remediate-teams-chat.ps1
#>

#region Initialize

# Initialize execution summary variable. 
# Will collect brief messages of actions and errors, helps troubleshoot easily even directly form Microsoft Intune console.
$execSummary = @()

# Allows for disgnostics log. Non-zero = error at some point of execution.
$status = 0

# Define the application identifier for Microsoft Teams Chat
$MSTeams = "MicrosoftTeams"

#endregion Initialize

#region Functions

function Enable-Privilege {
    param(
        [string]$Privilege
    )
    <#
    .SYNOPSIS
    Enables a specific privilege for the current process.

    .DESCRIPTION
    This function uses platform invocation (P/Invoke) to call Windows API functions
    to adjust the token privileges of the current process, allowing it to enable
    privileges such as 'SeTakeOwnershipPrivilege'. This is necessary for operations
    that require elevated privileges beyond those normally granted, even to administrative users.

    .PARAMETER Privilege
    The name of the privilege to enable, e.g., 'SeTakeOwnershipPrivilege'.

    .EXAMPLE
    Enable-Privilege -Privilege "SeTakeOwnershipPrivilege"

    .NOTES
    Based on techniques discussed in Windows API documentation and adapted for PowerShell use.
    Original concept and code snippets can be attributed to various sources on Windows
    security programming, with adaptations for PowerShell.

    Source: https://superuser.com/questions/1814310/change-ownership-of-registry-key-using-script

    #>
    # Add-Type code snippet with Windows API function declarations for adjusting privileges
    $definition = @'
using System;
using System.Runtime.InteropServices;

public class Privilege {
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
        ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TokPriv1Luid {
        public int Count;
        public long Luid;
        public int Attr;
    }

    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

    public static bool EnablePrivilege(long processHandle, string privilege) {
        bool retVal;
        TokPriv1Luid tp;
        IntPtr hproc = new IntPtr(processHandle);
        IntPtr htok = IntPtr.Zero;
        retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
        tp.Count = 1;
        tp.Luid = 0;
        tp.Attr = SE_PRIVILEGE_ENABLED;
        retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
        retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        return retVal;
    }
}
'@
    # Using Add-Type to compile and load the above C# code snippet into the current PowerShell session.
    Add-Type -MemberDefinition $definition -Name 'Privilege' -Namespace 'PrivilegeAdjust'
    # Getting the current process handle.
    $processHandle = (Get-Process -id $pid).Handle
    # Calling the EnablePrivilege method to enable the specified privilege for the current process.
    [PrivilegeAdjust.Privilege]::EnablePrivilege($processHandle, $Privilege)
}

function TakeOwnership-RegistryKey {
    param(
        [string]$RegistryPath
    )
    <#
    .SYNOPSIS
    Takes ownership of a specified registry key.

    .DESCRIPTION
    This function changes the ownership of a registry key to the Administrators group,
    enabling subsequent modifications to the key's permissions or values. It first
    attempts to enable the 'SeTakeOwnershipPrivilege' for the current process, then
    uses .NET's RegistryKey class to change the key's ownership.

    .PARAMETER RegistryPath
    The full path to the registry key for which ownership will be taken, in PowerShell
    registry path format (e.g., 'HKLM:\SOFTWARE\MySoftware').

    .EXAMPLE
    TakeOwnership-RegistryKey -RegistryPath "HKLM:\SOFTWARE\MySoftware"

    .NOTES
    This function is part of a script designed to automate the removal of Microsoft Teams Chat
    and similar tasks, requiring elevated privileges to modify system registry keys.
    Adapted from techniques commonly used in system administration scripting for Windows.
    
    Source: https://superuser.com/questions/1814310/change-ownership-of-registry-key-using-script

    #>
    # Convert the PowerShell registry path to a .NET-compatible format by removing the 'HKLM:\' prefix
    $netRegistryPath = $RegistryPath -replace '^HKLM:\\', '' # For HKLM keys

    # Dynamically identify the name of the Administrators group
    $expectedAdminGroupName = (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate([System.Security.Principal.NTAccount]).Value

    # Enable the 'take ownership' privilege
    Enable-Privilege -Privilege "SeTakeOwnershipPrivilege"
    
    try {
        # Open the registry key with write access
        $registryKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($netRegistryPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
        # Create a new ACL object and set the owner to the Administrators group
        $acl = New-Object System.Security.AccessControl.RegistrySecurity
        $acl.SetOwner([System.Security.Principal.NTAccount]$expectedAdminGroupName)
        # Apply the new ACL to the registry key
        $registryKey.SetAccessControl($acl)
        # Close the registry key handle
        $registryKey.Close()
        Write-Host "Successfully took ownership of $RegistryPath."
    } catch {
        Write-Host "Failed to take ownership of $RegistryPath. Error: $_"
    }
}

#endregion Functions

#region Main

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

# The well-known SID for the Administrators group is consistent across Windows installations, ensuring the correct group is targeted.
$expectedAdminGroupName = (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate([System.Security.Principal.NTAccount]).Value


# Prior to taking ownership, enable privilege.
Enable-Privilege -Privilege "SeTakeOwnershipPrivilege"

# Take ownership of the registry key to enable further configurations
TakeOwnership-RegistryKey -RegistryPath $registryPath

# After taking ownership, set permissions
try {
    # Refresh the ACL object after taking ownership
    $acl = Get-Acl -Path $registryPath

    # Create an access rule that grants full control to the Administrators group
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule($expectedAdminGroupName, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")

    # Add the access rule to the ACL
    $acl.AddAccessRule($rule)

    # Apply the modified ACL back to the registry key
    Set-Acl -Path $registryPath -AclObject $acl

    Write-Host "Permissions successfully modified for the Administrators group."
    $execSummary += "Reg. Permissions Modified"
} catch {
    Write-Host "Failed to modify permissions: $_"
    $execSummary += "Error Modifying Permissions"
    $status = 4 # Use a unique status code to indicate a permissions modification error
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
}

#  Fin!!

#endregion Main
