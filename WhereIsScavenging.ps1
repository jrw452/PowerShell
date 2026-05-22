$DCs = Import-Csv ".\AllDCs.csv"
$DCs | Add-Member -MemberType NoteProperty -Name Enabled -Value '--'
Foreach ($DC in $Dcs) {
    "Checking $($DC.Name)"
    $Check = Get-DnsServerScavenging -ComputerName $($DC.Name)
    $DC.Enabled = $Check.ScavengingState
    $Check = $null
}
$DCs | Export-Csv -NoTypeInformation ".\AllDCsChecked.csv"
