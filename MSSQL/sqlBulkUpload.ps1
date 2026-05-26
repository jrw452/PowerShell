<#
    A function to perform a SQL Bulk update from a PowerShell, tested with up to 50k rows of data.
    > AccessToken is the token string returned from Get-AZAccessToken
    > ObjectToUpload has been tested with results of a json return from Invoke-AzOperationalInsightsQuery and imported CSV objects resulting in PSCustomObject types.
    > SQLServer,Database,DBTable should be self explanatory

    Don't forget that the number of columns in your object and the data types should match the table.

    V1 - jrw452 - initial version
#>

function sqlBulkUpload {
    Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         $ObjToUpload,
         [Parameter(Mandatory=$true, Position=1)]
         [string]$AccessToken,
         [Parameter(Mandatory=$true, Position=2)]
         $SQLServer,
         [Parameter(Mandatory=$true, Position=3)]
         $Database,
         [Parameter(Mandatory=$true, Position=4)]
         $DBTable,
         [Parameter(Mandatory=$false, Position=5)]
         $batchsize = 50000
    )  
    
    "$(Get-date -Format 'yyyyMMdd HH:mm:ss') - Bulk insert func entered."  

    # Create SQL Connection
    $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
    $SqlConnection.AccessToken = $AccessToken
    $SqlConnection.ConnectionString = "Server=$SQLServer;Database=$Database;"
    $SqlConnection.Open()

    # Create a new bulk copy operation with the connection we've already established:
    $bulkcopy = New-Object System.Data.SqlClient.SqlBulkCopy($SqlConnection)
    $bulkcopy.DestinationTableName = $DBTable
    $bulkcopy.BatchSize = $batchsize

    $datatable = New-Object System.Data.DataTable

    foreach ($column in ($ObjToUpload | gm | Where-Object {$_.MemberType -eq 'NoteProperty'})) {
        $null = $datatable.Columns.Add()
    }
    
    # Add a row to the table for each line in the CSV. Can also use a datareader object and split the line on the delimiter but this causes problems for lines with commas in the data.
    Foreach ($line in $ObjToUpload) {
        $null = $datatable.Rows.Add($line.psobject.properties.value)

        if ($datatable.Rows.Count -ge $batchsize) {
            "$(Get-date -Format 'yyyyMMdd HH:mm:ss') - Uploading to SQL..."
            $bulkcopy.WriteToServer($datatable)
            $datatable.Clear()
        }
    }
    
    # final write for the remaining rows < the batch size:
    if ($datatable.Rows.Count -gt 0) {
        "$(Get-date -Format 'yyyyMMdd HH:mm:ss') - Final upload to SQL..."
        $bulkcopy.WriteToServer($datatable)
        $datatable.Clear()
    }
    $bulkcopy.Close()
    "$(Get-date -Format 'yyyyMMdd HH:mm:ss') - Bulk insert func complete."
}
