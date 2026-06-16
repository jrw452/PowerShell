<#
    Diagnostic DNS log gatherer.
    Aimed at gathering data as to whether Dynamci updates to DNS records are secure or not.
    Designed to be ran as a Scheduled Task that runs every 30mins or so on a DC.
    Will create a new ETL file on each run and analyse the last one, outputting CSV file with data.

        V1 - Base Script
        V2 - Added decoding of PaketData Field from log. Commented out (see line 66).
        V3 - robocopy and improvements
        V4 - Added AD site referencing.
        V5 - Changed to only keep one IPAddress + secure match per file, reduces file size to 1/3 of what it was in V4.
        V6 - Changed matchallkeyword bitmask:
        
        KeywordName     KeyWordValue       EventID
        -----------     ------------       -------
        DYN_UPDATE_RECV 0x0000000000000080     263
        
        KeywordName         KeyWordValue       EventID
        -----------         ------------       -------
        DYN_UPDATE_RESPONSE 0x0000000000000100     264

        Bitmask is now 180 from 80 to catch dynamic update replies 3(success/fails) from event 263 in event 264

        V7 - Changed to add new event - 519:

        KeywordName          KeyWordValue       EventID
        -----------          ------------       -------
        AUDIT_REC_DYN_UPDATE 0x0000000002000000     519

        Bitmask is now 2000180 from 180 to catch dynamic update replies (success/fails) from event 263 in event 264 and 519.

        V7 - JWA303 - Added additional script that pulls info from the event log and joins it with the existing script output, reduced overall events to those where an actual update/create has happened.
        V9 - JWA303 - Added DNS lookup to get timestamp from record.
        V10 - JWA303 - Added DNS to DSA lookup for record AD object to get security in cases where the lookup to the previous CSV doesn't return anything.
#>


$folders = @('Archive','Output','Logs','Output2')

# Test for each folder:
Foreach ($folder in $folders) {
    if (!(test-path "$PSScriptRoot\$Folder")) {
        New-Item -ItemType Directory -Path "$PSScriptRoot\$Folder"
    }  
}

$h = hostname

[string]$filename=$h + '_' + (get-date -Format 'yyyyMMdd-HH.mm.ss')

Start-Transcript -Path "$PSScriptRoot\Logs\$filename.txt"

# Get the trace session and stop it if its running:
if (Get-EtwTraceSession -Name DNSETWTrace -ErrorAction SilentlyContinue) {
    "Stopping ETW Trace."
    Stop-EtwTraceSession -Name DNSETWTrace
}

#Get any etl files that may have been created:
$AllETW = Get-ChildItem $PSScriptRoot -Filter "*.etl"

#Start a new trace session immediately, less chance of missing updates:
try {
    "Starting ETW Trace."
    Start-EtwTraceSession -Name DNSETWTrace -LocalFilePath "$PSScriptRoot\$filename.etl" -RealTime
    "Adding ETW TraceProvider."
    Add-EtwTraceProvider -SessionName DNSETWTrace -Guid "EB79061A-A566-4698-9119-3ED2807060E7" -level 5 -matchanykeyword 0x0000000002000180
} catch {
    "Failed to Set ETW. Error is $($_.exception.message)"
}

# ETW work for initial script:
if ($AllETW) {
    #Now process the files we have:
    $Allevents = @()
    Foreach ($f in $AllETW) {
        $Allevents += (Get-WinEvent -path $f.fullname -Oldest) | Where-Object {$_.Id -eq '263'} #Need this final filter as there's always a blank event first, and indexing into a null array will cause problems.
        Move-Item -Path $f.fullname -Destination "$PSScriptRoot\Archive" -Force
    }

    # Now format the events we have:
    if ($Allevents) {
        $Fevent = @()
        $Allevents | ForEach-Object {
            $Split = $_.Message.split(";")
            $FEvent += $_ | select @{N='DCO';E={$h}},@{N='DateTime';E={Get-date ($_.TimeCreated) -F 'yyyy-MM-dd HH:mm:ss' }},
            @{N='Source';e={$Split[2].replace("Source=","").replace(" ","")}},
            @{N='Secure';e={$Split[7].replace("SECURE=","").replace(" ","")}}
            <#So whilst following does decode the PackedData, and does contain the record name being updated, the output is very messy and will be difficult to parse reliably:
            ,@{N='PData';e={$123 = ($Split[-1].replace("PacketData=0x","").replace(" ","") -split '(?<=\G.{2})' -match '\S' | ForEach-Object {[char][byte]"0x$_"}); $123 -join ''}} 
            #>
        }
        if ($Fevent) {

            # Get only 1 entry per file. We don't care about granularity to a resolution of greater than 30mins.
            $Fevent = $Fevent | Group-Object Source,Secure | ForEach-Object {$_.Group[0]}

            $Fevent | Add-Member -MemberType NoteProperty -Name Subnet -Value ''
            $sitelist = Import-Csv $PSScriptRoot\sitelist.csv
            # Match the subnet to a sitename from DSSITE. Work out yourself how to get this file ;)
            foreach ($i in $Fevent) {
                if (($i.Source -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")) { 
                    [System.Net.IPAddress]$IPAddress = $I.Source
                    if ($IPAddress) {
                        foreach ($site in $sitelist) {
                            [System.Net.IPAddress]$Subnet = $site.SubnetIP
                            [System.Net.IPAddress]$SubnetMask = $site.SubnetMask
                            #"subnetIP is $($site.subnetIP), subnetmask is $($site.subnetmask)"
                            if ($Subnet.Address -eq ($IPaddress.Address -band $SubnetMask.Address)) {
                                $I.Subnet = $Site.SiteName 
                                break
                            }
                        }
                        $IPAddress = $null
                    }
                }
            }

            $filename=$h + '_' + (get-date -Format 'yyyyMMdd-HH.mm.ss')
            $Fevent | Export-Csv -NoTypeInformation "$PSScriptRoot\Output\$filename.csv"
            robocopy "$PSScriptRoot\Output\" "<DestinationCentralShare>" "$filename.csv" /e
        }
    } else {
        "No Events."
    }
} else {
    "No ETW Files to process."
}

#EVTLog work for second script:
$Thirty = (Get-Date) - (New-TimeSpan -minutes 35)
$AuditEvts = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-DNSServer/Audit'; StartTime=$Thirty; Id='519' }

if ($AuditEvts) {
    # Process these eventlog entries:
    $Fevent = @()
    Foreach ($i in $AuditEvts) {

        $Split = $i.Message.split(",")
        $Ty = ($Split[0] | select -last 2).replace("A resource record of type","").trim()
        Switch ($ty) {
            {$ty -eq "1"} {$Type = "A";break}
            {$ty -eq "16"} {$Type = "TXT";break}
            {$ty -eq "12"} {$Type = "PTR";break}
            {default} {$Type = $Ty}
        }
    
        if ($Type -eq "PTR") {
            $T = $null
            $i.message.split("x")[1].split(" ")[0] -split '(?<=\G.{2})'  -match '\S' |ForEach-Object {[string]$T += [char][byte]"0x$_"}
            # Remove all the non-visible formatting vhars that come from the byting:
            $t = $t -replace '[^0-9a-zA-Z-]'
            if ($T -like "*<DOMAINNAMEHERE>*") {[string]$Name = $T -replace "<DOMAINNAMEHERE>",""} #domain name with just letters (no dots or spaces)
        } else {
            $Name = $Split[1].replace(" name ","")
        }
        $Source = $Split[-1].split("Address")[-1].trimend(".").trim(" ")

        $Fevents = New-Object psobject
        $Fevents | Add-Member -MemberType NoteProperty -Name 'DCO' -Value $h
        $Fevents | Add-Member -MemberType NoteProperty -Name 'DateTime' -Value $(Get-date ($i.TimeCreated) -F 'yyyy-MM-dd HH:mm:ss')
        $Fevents | Add-Member -MemberType NoteProperty -Name 'Source' -Value $Source
        $Fevents | Add-Member -MemberType NoteProperty -Name 'Type' -Value $Type
        $Fevents | Add-Member -MemberType NoteProperty -Name 'Name' -Value $Name
        $Fevents | Add-Member -MemberType NoteProperty -Name 'Timestamp' -Value ''
        $Fevents | Add-Member -MemberType NoteProperty -Name 'Secure' -Value ''
        $Fevents | Add-Member -MemberType NoteProperty -Name 'Subnet' -Value ''
        $Fevent += $Fevents
    }

    #Poll the last few CSVs for comparison:
    Gci C:\InsecureDNS\Output -Filter "*.csv"  | Where-Object {$_.LastWriteTime -gt ((Get-date).AddMinutes(-66))} | ForEach-Object {$CSV += Import-Csv $_.FullName}

    Foreach ($i in $Fevent) {
    
        $c = ($CSV | Where-Object {$_.Source -eq $i.Source}) | select -Unique
        $NoSecureData = $null
        if ($C) {
            $SecureS = 0; $InsecS = 0
            foreach ($j in $c) {
                if ($j.Secure -eq "1") {$SecureS++} else {$InsecS++}
            }
    
            if (($SecureS -gt 0) -and ($InsecS -eq 0)) {$i.Secure = 1}
            elseif (($SecureS -eq 0) -and ($InsecS -gt 0)) {$i.Secure = 0}
            elseif (($SecureS -eq 0) -and ($InsecS -eq 0)) {$i.Secure = "UNKNOWN"}
            elseif (($SecureS -gt 0) -and ($InsecS -gt 0)) {$i.Secure = "UNKNOWN"}
        
        } else {
            $i.Secure = "NoData"
            $NoSecureData = 1
        }
        $i.subnet = $c.Subnet
        $C = $null

        if ($i.Type -ne 'PTR') {
            $DNSTimestamp = Get-DnsServerResourceRecord -RRType $i.Type -ZoneName "<ZoneNametoLookup>" -ComputerName localhost -Name $i.Name #fqdn of the zone
        } else {
            $ReverseIP = ($i.Source).split(".")[3..1] -join '.'
            $DNSTimestamp = Get-DnsServerResourceRecord -RRType $i.Type -ZoneName "<ReverseZone>" -ComputerName localhost -Name $ReverseIP #in-addr.arpa name, ie: 10.in-addr.arpa
        }
        if ($DNSTimestamp) {
            $Dynamic=0; $NonDynamic = 0
            foreach ($j in $DNSTimestamp) {
                if ($j.Timestamp) {
                    $Dynamic++
                } else {
                    $NonDynamic++
                }
            }
            if (($Dynamic -gt 0) -and ($NonDynamic -eq 0)) {$TS = 1}
            elseif (($Dynamic -eq 0) -and ($NonDynamic -gt 0)) {$TS = 0}
            elseif (($Dynamic -eq 0) -and ($NonDynamic -eq 0)) {$TS = 'Unknown'}
            elseif (($Dynamic -gt 0) -and ($NonDynamic -gt 0)) {$TS = 'Both'}
            $i.Timestamp = $TS

            if ($NoSecureData -eq 1) {
                # There's no Security info from the other CSV, but we can potentially get this from the DNS record itself:
                $ComputeronACL = (Get-ACL -path "AD:\$($DNSTimestamp.DistinguishedName)").Access | Where-Object {$_.IdentityReference -like "*$*"}
                if ($ComputeronACL) {
                    "Used DNS to ACL lookup to get security on record"
                    $i.Secure = 1
                } else {
                    $i.Secure = 0
                }
                $NoSecureData = $null
                $ComputeronACL = $null
            }
        } else {
            $i.Timestamp = 'NoData'
        }
    }

    # Export this additional file.
    $Fevent | Export-Csv -NoTypeInformation "$PSScriptRoot\Output2\$filename.csv"
    robocopy "$PSScriptRoot\Output2\" "\\<TargetcollationServer>\InsecureDNS$\Outputs2\" "$filename.csv" /e # Share on the server where all the DCOs send their logs for collation

} else {
    "No Log2 Files to process."
}
#Cleanup:
Foreach ($folder in $folders) {
    Get-ChildItem "$PSScriptRoot\$Folder" | Where-Object {$_.LastWriteTime -lt ((Get-date).AddDays(-1))} | Remove-Item -Force
}

Stop-Transcript
