Function Get-MAAFunction {
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

	$logon_sessions = @(Get-WmiObject win32_logonsession -ComputerName $computername)
	$logon_users = @(Get-WmiObject win32_loggedonuser -ComputerName $computername)

	$session_user = @{}

	$logon_users | ForEach-Object {
		$_.antecedent -match $regexa > $nul
		$username = $matches[1] + "\" + $matches[2]
		$_.dependent -match $regexd > $nul
		$session = $matches[1]
		$session_user[$session] += $username
	}


	$logon_sessions | ForEach-Object{
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

Function fileSizeOutput {
<#
	.SYNOPSIS
		Convert input integer to pretty GB/MB/KB format
	.DESCRIPTION
		Returns (convert) size in format #.### GB/MB/KB
	.PARAMETER Size
		Input integer parameter without chars
	.EXAMPLE
		fileSizeOutput 10250
		Returns 10,01 KB
	.LINK
		https://github.com/ripev/PowerShell/tree/master/MAAFunctions#filesizeoutput
	.NOTES
		NAME fileSizeOutput
		AUTHOR: Andrey Makovetsky (andrey@makovetsky.me)
		LASTEDIT: 2018-03-29
#>
	param ([Parameter (Mandatory=$true,Position=0)]$Size)
	if ($Size -ge 1073741824) { # check that size in GB
		($($Size)/1073741824).ToString("#.###") + " GB"
	} else {
		if ($Size -ge 1048576) { # check that size in MB
			($($Size)/1048576).ToString("#.###") + " MB"
		} else { # check that size in KB
			($($Size)/1024).ToString("#.###") + " KB"
		}
	}
}

Function Set-PSWindowTitle {
<#
	.SYNOPSIS
		Set powershell window title
	.PARAMETER title
		Title string to display
	.EXAMPLE
		Set-PSWindowTitle -Title "Test PS"
		Set PS title to 'Test PS'
	.LINK
		https://github.com/ripev/PowerShell/tree/master/MAAFunctions#set-pswindowtitle
	.NOTES
		NAME Set-PSWindowTitle
		AUTHOR: Andrey Makovetsky (andrey@makovetsky.me)
		LASTEDIT: 2018-05-31
#>
	param (
		[Parameter (Mandatory=$true,Position=0)]
			[String] $Title
	)
	# Checks that script not running in PowerShell ISE
	if (!$psISE) {
		$host.ui.RawUI.WindowTitle = $Title
	}
}

Function Get-PSWindowTitle {
<#
	.SYNOPSIS
		Get powershell window title
	.DESCRIPTION
		Returns string from current running powershell window
	.LINK
		https://github.com/ripev/PowerShell/tree/master/MAAFunctions#get-pswindowtitle
	.NOTES
		NAME Get-PSWindowTitle
		AUTHOR: Andrey Makovetsky (andrey@makovetsky.me)
		LASTEDIT: 2018-05-31
#>
	# Checks that script not running in PowerShell ISE
	if (!$psISE) {
		$host.ui.RawUI.WindowTitle
	} else {
		$null
	}
}

Function timeDurationOutput {
	<#
	.SYNOPSIS
		Show time duration in readable format
	.DESCRIPTION
		Returns (convert) size in format #.### GB/MB/KB
	.PARAMETER duration
		Input timespan to output
	.PARAMETER nColor
		Specify color for digits
	.PARAMETER sColor
		Specify color for strings
	.PARAMETER NoNewLine
		No new line after output
	.EXAMPLE
		timeDurationOutput [timespan]$duration
		Outputs duration in '1 h 13 m 34 s' format
	.LINK
		https://github.com/ripev/PowerShell/tree/master/MAAFunctions#timeDurationOutput
	.INPUTS
		[System.TimeSpan]
	.OUTPUTS
		[System.String]
	.NOTES
		NAME timeDurationOutput
		AUTHOR: Andrey Makovetsky (andrey@makovetsky.me)
		LASTEDIT: 2018-06-06
#>
	param (
		[Parameter (Mandatory=$true,Position=0)]
			[TimeSpan] $duration,
		[Parameter (Mandatory=$false)]
			[ValidateSet("Black","DarkBlue","DarkGreen","DarkCyan","DarkRed","DarkMagenta","DarkYellow","Gray","DarkGray","Blue","Green","Cyan","Red","Magenta","Yellow","White")]
			[String] $nColor = "Yellow",
		[Parameter (Mandatory=$false)]
			[ValidateSet("Black","DarkBlue","DarkGreen","DarkCyan","DarkRed","DarkMagenta","DarkYellow","Gray","DarkGray","Blue","Green","Cyan","Red","Magenta","Yellow","White")]
			[String] $sColor = "Gray",
		[Parameter (Mandatory=$false)]
			[Switch] $NoNewLine
	)
	function NScolorOut {
		param (
			[Parameter (Mandatory=$true,Position=0)]
				[int] $n,
			[Parameter (Mandatory=$true,Position=1)]
				[string] $s,
			[Parameter (Mandatory=$false)]
				[Switch] $NoNewLine
		)
		Write-Host $n -ForegroundColor $nColor -NoNewline
		Write-Host $s -ForegroundColor $sColor -NoNewline
		if (!$NoNewLine) {Write-Host ""}
	}
	$hoursWithoutDays = [math]::Round($duration.TotalHours % 24)
	$minutesWithoutHours = [math]::Round($duration.TotalMinutes % 60)
	$secondsWithoutMinutes = [math]::Round($duration.TotalSeconds % 60)
	# Days output
	if ([math]::Round($duration.TotalDays) -gt 0) {
		NScolorOut $duration.TotalDays " d" -NoNewLine
		if ($hoursWithoutDays -gt 0 -or $minutesWithoutHours -gt 0 -or $secondsWithoutMinutes -gt 0) {
			Write-Host " " -NoNewline
		}
	}
	# Hours output
	if ($duration.TotalHours -gt 0 -and $hoursWithoutDays -gt 0) {
		NScolorOut $($duration.TotalHours % 24) " h" -NoNewLine
		if ($minutesWithoutHours -gt 0 -or $secondsWithoutMinutes -gt 0) {
			Write-Host " " -NoNewline
		}
	}
	# Minutes output
	if ($duration.TotalMinutes -gt 0 -and $minutesWithoutHours -gt 0) {
		NScolorOut $minutesWithoutHours " m" -NoNewLine
		if ($secondsWithoutMinutes -gt 0) {
			Write-Host " " -NoNewline
		}
	}
	# Seconds output
	if ($duration.TotalSeconds -gt 0 -and $secondsWithoutMinutes -gt 0) {
		NScolorOut $secondsWithoutMinutes " s" -NoNewLine
	}
	if (!$NoNewLine) {Write-Host ""}
}

function Get-LockedFileProcess {
<#
	.Synopsis
		Get process thats lock the file
	.Description
		Search (Get-Process).Modules to file needed
	.Example
		Get-LockedFileProcess linq2db.pdb
		Show process name with pid that uses this file
	.Link
		https://beamusupscotty.wordpress.com/2012/11/14/use-powershell-to-find-out-which-process-locks-a-file/
	.Inputs
		System.String[]
	.Outputs
		System.String[]
	.Notes
	NAME: Get-LockedFileProcess
	AUTHOR: Alex Flipovici
#>
	param (
		[Parameter (Mandatory=$true,Position=0)]
			[string] $lockedFile
	)
	Get-Process | ForEach-Object {
		$processVar = $_
		$_.Modules | ForEach-Object {
			if ($_.FileName -match $lockedFile) {
				Write-Host $($processVar.Name) -NoNewline
				Write-Host " PID: " -ForegroundColor Gray -NoNewline
				Write-Host $($processVar.id) -ForegroundColor Yellow
			}}}
}

function Select-ColorString {
<#
	.SYNOPSIS
		Find the matches in a given content by the pattern and write the matches in color like grep
	.NOTES
		inspired by: https://ridicurious.com/2018/03/14/highlight-words-in-powershell-console/
	.EXAMPLE
		'aa bb cc', 'A line' | Select-ColorString a
		Both line 'aa bb cc' and line 'A line' are displayed as both contain "a" case insensitive
	.EXAMPLE
		'aa bb cc', 'A line' | Select-ColorString a -NotMatch
		Nothing will be displayed as both lines have "a"
	.EXAMPLE
		'aa bb cc', 'A line' | Select-ColorString a -CaseSensitive
		Only line 'aa bb cc' is displayed with color on all occurrences of "a" case sensitive
	.EXAMPLE
		'aa bb cc', 'A line' | Select-ColorString '(a)|(\sb)' -CaseSensitive -BackgroundColor White
		Only line 'aa bb cc' is displayed with background color White on all occurrences of regex '(a)|(\sb)' case sensitive
	.EXAMPLE
		'aa bb cc', 'A line' | Select-ColorString b -KeepNotMatch
		Both line 'aa bb cc' and 'A line' are displayed with color on all occurrences of "b" case insensitive,
	.EXAMPLE
		Get-Content "C:\Windows\Logs\DISM\dism.log" -Tail 100 -Wait | Select-ColorString win
		Find and color the keyword "win" in the last ongoing 100 lines of dism.log
	.EXAMPLE
		Get-WinEvent -FilterHashtable @{logname='System'; StartTime = (Get-Date).AddDays(-1)} | Select-Object time*,level*,message | Select-ColorString win
		Find and color the keyword "win" in the System event log from the last 24 hours
#>
	[Cmdletbinding(DefaultParametersetName = 'Match')]
	Param(
		[Parameter(Position = 0)][ValidateNotNullOrEmpty()]
		[String]$Pattern = $(throw "$($MyInvocation.MyCommand.Name) : " `
			+ "Cannot bind null or empty value to the parameter `"Pattern`""),

		[Parameter(ValueFromPipeline = $true,
			HelpMessage = "String or list of string to be checked against the pattern")]
		[String[]]$Content,

		[Parameter()]
		[ValidateSet(
			'Black',
			'DarkBlue',
			'DarkGreen',
			'DarkCyan',
			'DarkRed',
			'DarkMagenta',
			'DarkYellow',
			'Gray',
			'DarkGray',
			'Blue',
			'Green',
			'Cyan',
			'Red',
			'Magenta',
			'Yellow',
			'White')]
		[String]$ForegroundColor = 'Yellow',
		[Parameter()]
		[ValidateSet(
			'Black',
			'DarkBlue',
			'DarkGreen',
			'DarkCyan',
			'DarkRed',
			'DarkMagenta',
			'DarkYellow',
			'Gray',
			'DarkGray',
			'Blue',
			'Green',
			'Cyan',
			'Red',
			'Magenta',
			'Yellow',
			'White')]
		[ValidateScript( {
			if ($Host.ui.RawUI.BackgroundColor -eq $_) {
				throw "Current host background color is also set to `"$_`", " `
					+ "please choose another color for a better readability"
				}
			else {
				return $true
			}
		})]
		[String]$BackgroundColor = $Host.ui.RawUI.BackgroundColor,
		[Parameter()]
		[Switch]$CaseSensitive,

		[Parameter(
			ParameterSetName = 'NotMatch',
			HelpMessage = "If true, write only not matching lines; " `
				+ "if false, write only matching lines")]
		[Switch]$NotMatch,
		[Parameter(
			ParameterSetName = 'Match',
			HelpMessage = "If true, write all the lines; " `
				+ "if false, write only matching lines")]
		[Switch]$KeepNotMatch
	)
	begin {
		$paramSelectString = @{
			Pattern       = $Pattern
			AllMatches    = $true
			CaseSensitive = $CaseSensitive
		}
		$writeNotMatch = $KeepNotMatch -or $NotMatch
	}
	process {
		foreach ($line in $Content) {
			$matchList = $line | Select-String @paramSelectString
			if (0 -lt $matchList.Count) {
				if (-not $NotMatch) {
					$index = 0
					foreach ($myMatch in $matchList.Matches) {
						$length = $myMatch.Index - $index
						Write-Host $line.Substring($index, $length) -NoNewline
						$paramWriteHost = @{
							Object          = $line.Substring($myMatch.Index, $myMatch.Length)
							NoNewline       = $true
							ForegroundColor = $ForegroundColor
							BackgroundColor = $BackgroundColor
						}
						Write-Host @paramWriteHost
						$index = $myMatch.Index + $myMatch.Length
					}
					Write-Host $line.Substring($index)
				}
			}
			else {
				if ($writeNotMatch) {
					Write-Host "$line"
				}
			}
		}
	}
	end {
	}
}

function Get-DotNetVersion {
<#
	.Synopsis
		Get .net framework versions from Windows Registry
	.Description
		Get .net framework versions from Windows Registry
	.Link
		https://stackoverflow.com/questions/3487265/powershell-script-to-return-versions-of-net-framework-on-a-machine/3495491#3495491
#>
	$Lookup = @{
		378389 = [version]'4.5'
		378675 = [version]'4.5.1'
		378758 = [version]'4.5.1'
		379893 = [version]'4.5.2'
		393295 = [version]'4.6'
		393297 = [version]'4.6'
		394254 = [version]'4.6.1'
		394271 = [version]'4.6.1'
		394802 = [version]'4.6.2'
		394806 = [version]'4.6.2'
		460798 = [version]'4.7'
		460805 = [version]'4.7'
		461308 = [version]'4.7.1'
		461310 = [version]'4.7.1'
		461808 = [version]'4.7.2'
		461814 = [version]'4.7.2'
	}

	$regPath = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP'
	if (Test-Path $regPath -ErrorAction SilentlyContinue) {
		Get-ChildItem $regPath -Recurse |
			Get-ItemProperty -name Version, Release -EA 0 |
			# For One True framework (latest .NET 4x), change match to PSChildName -eq "Full":
				Where-Object { $_.PSChildName -match '^(?!S)\p{L}'} |
					Select-Object @{name = ".NET Framework"; expression = {$_.PSChildName}},
					@{name = "Product"; expression = {$Lookup[$_.Release]}},
					Version, Release
	} else {
		Write-Output "Reg path of .NET not found. .NET framework not installed or not considtent os version"
	}

}

function Get-Factorial ([int]$n) {
<#
	.Synopsis
		Get factorial from input int
	.Description
		Get factorial from input int
#>
	if ($n -eq 0) {[int]$t=1;$t}
	else {
		$factorial = 1;
		for ($i=1;$i -le $n;$i++){
			$factorial *= $i
		}
		$factorial
	}
}