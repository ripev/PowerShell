Function Invoke-SQLCustomScript {
<#
	.SYNOPSIS
		Sql script without installing Management Studio with integrated (windows) auth

	.PARAMETER SQLInstance
		SQL server adress

	.PARAMETER SQLDBName
		Database name

	.PARAMETER SQLScript
		Sql script to query
	
	.PARAMETER VerboseOutput
		Allow output text message after tsql execution

	.EXAMPLE
		Invoke-SQLCustomScript -SQLInstance localhost -SQLDBName master -SQLScript "Select name,user_access_desc from sys.databases"

		Get all databases from default local SQL server with state

	.LINK
		https://github.com/ripev/PowerShell/
#>
	Param (
		[Parameter(Mandatory=$true,Position=0)]
			[String] $SQLInstance,
		[Parameter(Mandatory=$true,Position=1)]
			[String] $SQLDBName,
		[Parameter(Mandatory=$true,Position=2)]
			[String] $SQLScript,
		[Parameter(Mandatory=$false,Position=3)]
			[String] $SQLLogin,
		[Parameter(Mandatory=$false,Position=4)]
			[String] $SQLPassword,
		[Parameter(Mandatory=$false)]
			[switch] $VerboseOutput,
		[Parameter(Mandatory=$false)]
			[String] $OutputFile,
		[Parameter(Mandatory=$false)]
			[String] $Timeout = 60000
	)
	$StartLocation = Get-Location
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlConnection.ConnectionString = "Server = $SQLInstance; Database = $SQLDBName; Integrated Security = "
	if (!$SQLLogin) {
		$SqlConnection.ConnectionString += "true;"
	} else {
		$SqlConnection.ConnectionString += "false; user id = $($SQLLogin); password = $($SQLPassword);"
	}
	if ($VerboseOutput) {
		if ($OutputFile) {
			if ((Test-Path $OutputFile) -eq $false) {
				New-Item $OutputFile -Type File | Out-Null
			} else {
				Remove-Item $OutputFile -Force
			}
			$handler = [System.Data.SqlClient.SqlInfoMessageEventHandler] {param($sender, $event) Write-Output $event.Message | Out-File $OutputFile -Encoding UTF8 -Append}
		} else {
			$handler = [System.Data.SqlClient.SqlInfoMessageEventHandler] {param($sender, $event) Write-Host $event.Message }
		}
		$SqlConnection.add_InfoMessage($handler)
		$SqlConnection.FireInfoMessageEventOnUserErrors = $true
	}
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlCmd.CommandText = $SQLScript
	$SqlCmd.Connection = $SqlConnection
	$SqlCmd.CommandTimeout = $Timeout
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$SqlAdapter.SelectCommand = $SqlCmd
	$DataSet = New-Object System.Data.DataSet
	$SqlAdapter.Fill($DataSet) | Out-Null
	$SqlConnection.Close()
	$DataSet.Tables[0]
	Set-Location $StartLocation
}