<# 
    Used to dynamically determine where Scavenging is enabled on each Domain Controller in each domain.
    Will require appropriate rights on each DC on each domain to run

    V1 - jrw452 - Inital Version
#>

$DCs = Import-Csv ".\AllDCs.csv"
$DCs | Add-Member -MemberType NoteProperty -Name Enabled -Value '--'
Foreach ($DC in $Dcs) {
    "Checking $($DC.Name)"
    $Check = Get-DnsServerScavenging -ComputerName $($DC.Name)
    $DC.Enabled = $Check.ScavengingState
    $Check = $null
}
$DCs | Export-Csv -NoTypeInformation ".\AllDCsChecked.csv"
