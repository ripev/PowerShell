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