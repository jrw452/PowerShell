<#
    A Script to bulk check the status' of multiple accounts in Active Directory in one go.
    Required a text file with a list of the SamAccountName vallues you want to check.

    V1 - jrw452 - initial version
#>

try {
    $Input = Get-Content ".\Users.txt"
} catch {
    "Failed to get source file. Error is $($_.exception.message)"
}

# The AD PDCe FSMO role should have authoritative data on account status. Determine this DC:
try {
    $PDCe = Get-ADDomain.PDCEmulator
} catch {
    "Failed to get PDCe from AD. Error is: $($_.exception.message)"
    "Please fix error and try again."
    Start-Sleep -s 600
    exit
}

$arr = @()
Foreach ($U in $Input) {
    "Looking at $U"
    # Copying from different sources into the file can leave rogue spaces, remove these:
    $U=$U.trim()

    $User = Get-ADUser -Identity $U -Properties lastlogontimestamp,badpwdcount,badpasswordtime,msDS-UserPasswordExpiryTimeComputed,pwdLastSet,whencreated,sn,givenName,PasswordNeverExpires,canonicalName  -Server $PDCe

    if ($User) {    

        $ex = $user.'msDS-UserPasswordExpiryTimeComputed'

        $i = New-Object psobject
        $i | Add-Member -MemberType NoteProperty -Name "User" -Value $U
        $i | Add-Member -MemberType NoteProperty -Name "Enabled" -Value $User.enabled
        $i | Add-Member -MemberType NoteProperty -Name "Gn" -Value $User.givenName
        $i | Add-Member -MemberType NoteProperty -Name "SN" -Value $User.sn
        $i | Add-Member -MemberType NoteProperty -Name "Location" -Value $User.canonicalName
        $i | Add-Member -MemberType NoteProperty -Name "Created" -Value $User.whencreated
        $i | Add-Member -MemberType NoteProperty -Name "LastLogonTimestamp" -Value $([datetime]::FromFileTime($User.lastlogontimestamp))
        $i | Add-Member -MemberType NoteProperty -Name "BadPwdCount" -Value "$($User.badpwdcount)"
        $i | Add-Member -MemberType NoteProperty -Name "BadPwdTime" -Value $([datetime]::FromFileTime($User.badpasswordtime))
        $i | Add-Member -MemberType NoteProperty -Name "PasswordExpires" -Value $([datetime]::FromFileTime($ex))
        $i | Add-Member -MemberType NoteProperty -Name "PwdLastSet" -Value $([datetime]::FromFileTime($User.pwdLastSet))
        $i | Add-Member -MemberType NoteProperty -Name "PwdNeverExpires" -Value $User.PasswordNeverExpires
        $Arr += $i
        $User = $null
    } else {
        "No user found with SAMAccountName: $U."
        $i = New-Object psobject
        $i | Add-Member -MemberType NoteProperty -Name "User" -Value $U
        $i | Add-Member -MemberType NoteProperty -Name "Enabled" -Value "User Not Found"
        $i | Add-Member -MemberType NoteProperty -Name "Gn" -Value "User Not Found"
        $i | Add-Member -MemberType NoteProperty -Name "SN" -Value "User Not Found"
        $i | Add-Member -MemberType NoteProperty -Name "Location" -Value "User Not Found"
        $i | Add-Member -MemberType NoteProperty -Name "Created" -Value "User Not Found"
        $i | Add-Member -MemberType NoteProperty -Name "LastLogonTimestamp" -Value "User Not Found"
        $i | Add-Member -MemberType NoteProperty -Name "BadPwdCount" -Value "User Not Found"
        $i | Add-Member -MemberType NoteProperty -Name "BadPwdTime"  -Value "User Not Found"
        $i | Add-Member -MemberType NoteProperty -Name "PasswordExpires" -Value "User Not Found"
        $i | Add-Member -MemberType NoteProperty -Name "PwdLastSet" -Value "User Not Found"
        $i | Add-Member -MemberType NoteProperty -Name "PwdNeverExpires" -Value "User Not Found"
        $Arr += $i
        $User = $null
    }
}

$Arr | Export-Csv -NoTypeInformation .\BulkUserCheckerOutput.csv
$Arr | Out-GridView -Wait

"Script complete. Output is in BulkUserCheckerOutput.csv"
