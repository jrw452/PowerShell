<#
    A Script to check the status' of an account in Active Directory across all Read/Write Domain Controllers.

    V1 - jrw452 - initial version
#>

$acc = (Read-Host -Prompt "Account to check").trim()

Import-module ActiveDirectory

$ADS = Get-ADDomainController -Filter * | Where-Object {$_.IsReadOnly -eq $false}
$arr = @()
Foreach ($S in $ADS) {
    "Checking $($S.Name)..."
    $U = Get-ADUser $acc -Server $($s.Hostname) -properties lastlogon,logoncount,badpwdcount,badpasswordtime,msDS-UserPasswordExpiryTimeComputed,pwdLastSet,lastlogontimestamp
    $ex = $u.'msDS-UserPasswordExpiryTimeComputed'
    $i = New-Object psobject
    $i | Add-Member -MemberType NoteProperty -Name "DC" -Value "$($s.Name)"
    $i | Add-Member -MemberType NoteProperty -Name "LastLogon" -Value $([datetime]::FromFileTime($U.lastlogon))
    $i | Add-Member -MemberType NoteProperty -Name "LastLogonTimestamp" -Value $([datetime]::FromFileTime($U.lastlogontimestamp))
    $i | Add-Member -MemberType NoteProperty -Name "LogonCount" -Value "$($u.logoncount)"
    $i | Add-Member -MemberType NoteProperty -Name "BadPwdCount" -Value "$($u.badpwdcount)"
    $i | Add-Member -MemberType NoteProperty -Name "BadPwdTime" -Value $([datetime]::FromFileTime($u.badpasswordtime))
    $i | Add-Member -MemberType NoteProperty -Name "PasswordExpires" -Value $([datetime]::FromFileTime($ex))
    $i | Add-Member -MemberType NoteProperty -Name "PwdLastSet" -Value $([datetime]::FromFileTime($U.pwdLastSet))
    $i | Add-Member -MemberType NoteProperty -Name "Enabled" -Value $U.enabled
    $Arr += $i
   
}
$Filepaff = ".\DCChecker-$ACC-$(get-date -Format 'yyyy-MM-dd-HHmm').csv"
$Arr | Export-Csv $Filepaff -NoTypeInformation
$arr | out-gridview -Title "Password history for $acc" -Wait
