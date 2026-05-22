<# 
    Used to dynamically determine where Scavenging is enabled on each Domain Controller in each domain. Whilst you can theoretically enable it on a RODC this is bad practice, but is included here for completeness. As well as the Domain Controller, don't forget to check which zones have scavenging enabled.
    Will require appropriate rights on each DC to run.

    V1 - jrw452 - Inital Version
    V2 - jrw452 - Updated for dynamic discovery of DCs.
#>

Import-Module ActiveDirectory

$DCs = Get-ADDomainController -filter * | select Hostname,IsReadOnly,ScavengingEnabled

Foreach ($DC in $Dcs) {
    "Checking $($DC.HostName)"
    try {
        $Check = Get-DnsServerScavenging -ComputerName $($DC.HostName)
        if ($Check) {
            $DC.ScavengingEnabled = $Check.ScavengingState
        } else {
            $DC.ScavengingEnabled = "No Data returned"
        }
    } catch {
        $DC.ScavengingEnabled = "Failed. Error is $($_.exception.message)"
    }
    $Check = $null
}

$DCs | Export-Csv -NoTypeInformation ".\AllDCsChecked.csv"
