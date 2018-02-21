Function Get-MAAFunctions {
<#
	.SYNOPSIS
		Show MAA functions

	.LINK
		https://github.com/ripev/PowerShell/
#>
    Get-Command | Where-Object {$_.ModuleName -eq "MAAFunctions"}
}

Function Get-LoggedOnUser {
	Param ([Parameter(Mandatory=$false,Position=0)][string] $computername = "localhost")

	$regexa = '.+Domain="(.+)",Name="(.+)"$'
	$regexd = '.+LogonId="(\d+)"$'

	$logontype = @{
		"0"="Local System"
		"2"="Interactive" #(Local logon)
		"3"="Network" # (Remote logon)
		"4"="Batch" # (Scheduled task)
		"5"="Service" # (Service account logon)
		"7"="Unlock" #(Screen saver)
		"8"="NetworkCleartext" # (Cleartext network logon)
		"9"="NewCredentials" #(RunAs using alternate credentials)
		"10"="RemoteInteractive" #(RDP\TS\RemoteAssistance)
		"11"="CachedInteractive" #(Local w\cached credentials)
	}

	$logon_sessions = @(gwmi win32_logonsession -ComputerName $computername)
	$logon_users = @(gwmi win32_loggedonuser -ComputerName $computername)

	$session_user = @{}

	$logon_users |% {
		$_.antecedent -match $regexa > $nul
		$username = $matches[1] + "\" + $matches[2]
		$_.dependent -match $regexd > $nul
		$session = $matches[1]
		$session_user[$session] += $username
	}


	$logon_sessions |%{
		$starttime = [management.managementdatetimeconverter]::todatetime($_.starttime)

		$loggedonuser = New-Object -TypeName psobject
		$loggedonuser | Add-Member -MemberType NoteProperty -Name "Session" -Value $_.logonid
		$loggedonuser | Add-Member -MemberType NoteProperty -Name "User" -Value $session_user[$_.logonid]
		$loggedonuser | Add-Member -MemberType NoteProperty -Name "Type" -Value $logontype[$_.logontype.tostring()]
		$loggedonuser | Add-Member -MemberType NoteProperty -Name "Auth" -Value $_.authenticationpackage
		$loggedonuser | Add-Member -MemberType NoteProperty -Name "StartTime" -Value $starttime

		$loggedonuser
	}

}

Function Output {
<#
	.SYNOPSIS
		Output on screen (and file) some string

	.DESCRIPTION
		Write-Host and Write-Output in one flacon :)

	.PARAMETER str
		String to output

	.PARAMETER outfile
		File path to output

	.PARAMETER color
		Colorized output to display

	.EXAMPLE
		Output -str "Kalya-malya" -color Red

		Output "Kalya-malya" on display with red color

	.EXAMPLE
		Output -str "Kalya-malya" -outfile .\output.txt

		Output "Kalya-malya" on display with white color and to file .\output.txt

	.LINK
		https://github.com/ripev/PowerShell/
#>
	Param (
		[string] $str,
		[string] $outfile,
		[ValidateSet("Black","DarkBlue","DarkGreen","DarkCyan","DarkRed","DarkMagenta","DarkYellow","Gray","DarkGray","Blue","Green","Cyan","Red","Magenta","Yellow","White")][string]$color="White"
	)
	if ($outfile) {Write-Output "$str" | Out-File "$outfile" -Encoding utf8 -Append}
	Write-Host "$str" -f $color
}

Function Test-Admin {
<#
	.SYNOPSIS
		Return false if script rinning without elevated admin permissions

	.LINK
		https://github.com/ripev/PowerShell/
#>

    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

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

Function New-CustomGuid {
<#
	.SYNOPSIS
		Generates GUID on system without New-GUID commandlet

	.LINK
		https://github.com/ripev/PowerShell/
#>
	[string]$guid = ""
	[array]$guidMask = "8","4","4","4","12"
	[string]$chars = "ABCDEF0123456789"
	foreach ($g in $guidMask) {
		$random = 1..$g | ForEach-Object { Get-Random -Maximum $chars.length }
        $private:ofs=""
        $guid += "-" + [String]$chars[$random]
	}
    $guid.Substring(1,36)
}

Function Test-Port {
<#
	.SYNOPSIS
		Test port connectivity
	.DESCRIPTION
		Returning true or false for requested port
	.PARAMETER ComputerName
		Defines server address
		Mandatory parameter
		No default value.
	.PARAMETER IPAddress
		Defines server IP address
		Mandatory parameter
		No default value.
	.PARAMETER Port
		Port address to check
		Mandatory parameter
		No default value.
	.LINK
		http://www.travisgan.com/2014/03/use-powershell-to-test-port.html
#>
	Param(
		[parameter(ParameterSetName='ComputerName', Position=0)]
		[string] $ComputerName,

		[parameter(ParameterSetName='IP', Position=0)]
		[System.Net.IPAddress] $IPAddress,

		[parameter(Mandatory=$true , Position=1)]
		[int] $Port
		)

	$RemoteServer = If ([string]::IsNullOrEmpty($ComputerName)) {$IPAddress} Else {$ComputerName};
    $test = New-Object System.Net.Sockets.TcpClient;
	Try {
		$test.Connect($RemoteServer, $Port);
		$true
	}
	Catch {
		$false
		$Error.Clear()
	}
	Finally {
		$test.Dispose();
	}
}
