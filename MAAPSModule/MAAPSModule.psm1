﻿$MAAPSModuleURLManifest = "https://raw.githubusercontent.com/ripev/PowerShell/master/MAAPSModule/MAAPSModule.psd1"
$MAAPSModuleURL = "https://raw.githubusercontent.com/ripev/PowerShell/master/MAAPSModule/MAAPSModule.psm1"

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

Function Get-MAAPSModuleInternetVersion {
<#
	.SYNOPSIS
		Get current MAAPSModule version from Github

	.LINK
		https://github.com/ripev/PowerShell/
#>
	$MAAPSModuleURLManifestDownloaded = (new-object net.webclient).DownloadString($MAAPSModuleURLManifest)
	$MAAPSModuleURLDownloaded = (new-object net.webclient).DownloadString($MAAPSModuleURL)
	$RandomNameString = Get-RandomName
	$psd1temp = $env:TEMP + "\" + $RandomNameString + ".psd1"
	$psm1temp = $env:TEMP + "\" + $RandomNameString + ".psm1"
	Write-Output $MAAPSModuleURLManifestDownloaded | Out-File $psd1temp -Encoding unicode
	Write-Output $MAAPSModuleURLDownloaded | Out-File $psm1temp -Encoding utf8
	$Output=@()
	$OutputItem = New-Object Object
	$OutputItem | Add-Member NoteProperty "Version"	(Test-ModuleManifest $psd1temp).Version
	$OutputItem | Add-Member NoteProperty "psdpath" $psd1temp
	$OutputItem | Add-Member NoteProperty "psmpath" $psm1temp
	$Output += $OutputItem
    $Output
}

Function Get-MAAPSModuleLocalVersion {
<#
	.SYNOPSIS
		Get current installed MAAPSModule version from profile

	.LINK
		https://github.com/ripev/PowerShell/
#>
	(Get-Module MAAPSModule).Version
}

Function Get-MAAPSModuleVerions {
<#
	.SYNOPSIS
		Get local and github versions of MAAPSModule

	.LINK
		https://github.com/ripev/PowerShell/
#>
	$InternetVersion = (Get-MAAPSModuleInternetVersion).Version
	Write-Host "Internet version of modules is:`t" -ForegroundColor Yellow -NoNewline
	Write-Host "$($InternetVersion.Major).$($InternetVersion.Minor).$($InternetVersion.Build).$($InternetVersion.Revision)" -ForegroundColor Green
	$LocalVersion = Get-MAAPSModuleLocalVersion
	Write-Host "Local version of modules is:`t" -ForegroundColor Yellow -NoNewline
	Write-Host "$($LocalVersion.Major).$($LocalVersion.Minor).$($LocalVersion.Build).$($LocalVersion.Revision)" -ForegroundColor Green
}

Function Get-MAACommands {
<#
	.SYNOPSIS
		Show MAA module commands

	.DESCRIPTION
		Alias for get-command from MAAPSModule

	.LINK
		https://github.com/ripev/PowerShell/
#>
    Get-Command | Where-Object {$_.ModuleName -eq "MAAPSModule"}
}

Function Update-MAAPSModule {
<#
	.SYNOPSIS
		Update MAAPSmodule

	.DESCRIPTION
		Update MAAPSModule from github

	.PARAMETER force
		Update local modules even versions is the same

	.EXAMPLE
		Update-MAAPSModule

		Update module

	.LINK
		https://github.com/ripev/PowerShell/
#>
	Param(
		[Parameter(Mandatory=$false,Position=0)][switch]$force
	)
	$Error.Clear()
	$MAAPSModulePath = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\MAAPSModule"
	$InternetVersionInfo = Get-MAAPSModuleInternetVersion
	$psd1temp = $InternetVersionInfo.psdpath
	$psm1temp = $InternetVersionInfo.psmpath
	$InternetVersion = $InternetVersionInfo.Version
	$LocalVersion = Get-MAAPSModuleLocalVersion
	if ($LocalVersion -eq $InternetVersion -and -not $force) {
		Write-Host "Local and internet version are equal. No updates needed." -ForegroundColor Yellow
	} else {
		try {
			if ($LocalVersion -eq $InternetVersion -and $force) {
				Write-Host "Forcing update of local modules" -ForegroundColor Yellow
			} else {
				Write-Host "Updating local version from '" -ForegroundColor Gray -NoNewline
				Write-Host "$($LocalVersion.Major).$($LocalVersion.Minor).$($LocalVersion.Build).$($LocalVersion.Revision)" -ForegroundColor Yellow -NoNewline
				Write-Host "' to '" -ForegroundColor Gray -NoNewline
				Write-Host "$($InternetVersion.Major).$($InternetVersion.Minor).$($InternetVersion.Build).$($InternetVersion.Revision)" -ForegroundColor Yellow -NoNewline
				Write-Host "'" -ForegroundColor Gray
			}
			Copy-Item "$psd1temp" "$MAAPSModulePath\MAAPSModule.psd1" -Force -ErrorAction Stop
			Copy-Item "$psm1temp" "$MAAPSModulePath\MAAPSModule.psm1" -Force -ErrorAction Stop
			Write-Host "Modules updated successfully. Reload PowerShell to apply changes." -ForegroundColor DarkCyan
		}
		catch {
			Write-Host "Copy error:" -ForegroundColor DarkGray
			Write-Host "$($Error.Exception)" -ForegroundColor Red
		}
	}
}

Function Update-MAAFunctions {
<#
	.SYNOPSIS
		Install or update MAA Functions to system folder

	.LINK
		https://github.com/ripev/PowerShell/
#>
	iex ((new-object net.webclient).DownloadString('https://raw.githubusercontent.com/ripev/PowerShell/master/MAAFunctions/MAAFunctionsInstall.ps1'))
}

Function Get-DCCredential {
<#
	.SYNOPSIS
		Subfunction used in connect functions (Connect-Remote, etc.)

	.LINK
		https://github.com/ripev/PowerShell/
#>
	$CredFilePath = "$($env:USERPROFILE)\.ssh\$($env:USERNAME).cred"
	$CredFile = Get-Item $CredFilePath
	try {
		$PwdSecureString = Get-Content "$CredFile" | ConvertTo-SecureString -ErrorAction Stop
	} catch {
		Output -str "File with credentials not found at '$CredFile'" -color Red
		Output -str "You can create credential file with folowing command:" -color Gray
		Output -str '$Credential = Get-Credential' -color Yellow
		Output -str '$Credential.Password | ConvertFrom-SecureString | Out-File $($env:USERPROFILE)\.ssh\$($env:USERNAME).cred'
	}
	New-Object System.Management.Automation.PSCredential -ArgumentList $($CredFile.BaseName), $PwdSecureString
}

Function Get-LocalDisk {
<#
    .SYNOPSIS
        Show fixed disk information

    .DESCRIPTION
        Show fixed disk information in table pane with AutoSize formatting

    .LINK
        https://github.com/ripev/PowerShell/
#>
	Param(
		[Parameter(Mandatory=$false,Position=0)][string]$comp="localhost"
	)
	Get-WmiObject Win32_Volume -ComputerName $comp | `
	where {$_.DriveType -eq 3 -and $_.DriveLetter} | `
	Select-Object `
		DriveLetter,Label,FileSystem,`
	@{l="FreeSpace";e={"$([math]::Round(($_.FreeSpace / 1GB), 2)) GB"}},`
	@{l="Size";e={"$([math]::Round(($_.Capacity / 1GB), 2)) GB"}} | `
	Sort-Object DriveLetter
}

Function Get-RunningSQLInstances {
<#
    .SYNOPSIS
        Show running SQL instances

    .DESCRIPTION
        Show local running SQL instances

    .LINK
        https://github.com/ripev/PowerShell/
#>
    Get-Service | Where-Object {($_.DisplayName -like 'SQL Server (*') -and ($_.Status -like 'Running')}
}

Function Get-SQLDbs {
<#
	.SYNOPSIS
		Show SQL db in selected instance

	.DESCRIPTION
		Show SQL db in selected instance with MDB and LDF sized

	.PARAMETER Instance
		Set instance parameter, from where to show DBs. Default is localhost

	.EXAMPLE
		Get-SQLDbs -Instance localhost

		Show list of DB from default instance

	.EXAMPLE
		Get-SQLDbs -Instance "localhost,1102"

		Show list of DB from instance with port 1102

	.LINK
		https://github.com/ripev/PowerShell/
#>
    Param (
		[parameter(Mandatory=$true,ValueFromPipeline=$true)]
			[String[]] $instance = "localhost",
		[parameter(Mandatory=$false)]
			[Switch] $all
	)
	$location = Get-Location
    [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | Out-Null
    $server = New-Object ('Microsoft.SqlServer.Management.Smo.Server') "$instance"
    $DBs = $server.databases
    $DBs = $DBs.Name
	if (!$all) {
		$DBs = $DBs | Where-Object {$_ -notmatch 'master' -and $_ -notmatch 'model' -and $_ -notmatch 'msdb' -and $_ -notmatch 'tempdb'} #все бд
	}
    $Output=@()
    foreach ($db in $DBs) {
		
		$query = "
			with fs
				as
			(
				select database_id, type, size * 8.0 / 1024 size
				from sys.master_files
			)
			select
				name,
				(select sum(size) from fs where type = 0 and fs.database_id = db.database_id) DataFileSizeMB,
				(select sum(size) from fs where type = 1 and fs.database_id = db.database_id) LogFileSizeMB
			from sys.databases db where name = '$db'
		"
		$dbinfo = Invoke-Sqlcmd -ServerInstance "$instance" -Query $query
        $OutputItem = New-Object Object
        $OutputItem | Add-Member NoteProperty "Name" $db
		$OutputItem | Add-Member NoteProperty "DataFileSizeMB" $dbinfo.DataFileSizeMB
		$OutputItem | Add-Member NoteProperty "LogFileSizeMB" $dbinfo.LogFileSizeMB
        $Output += $OutputItem
    }
    $Output
	Set-Location $location
}

Function Get-RandomPassword {
<#
	.SYNOPSIS
		Generate passowrd

	.DESCRIPTION
		Generate password with selected length and copy to clipboard. Default is 20.

	.PARAMETER length
		Integer parameter shows whith password length should be

	.EXAMPLE
		Get-RandomPassword

		Generate password with length 20

	.EXAMPLE
		Get-RandomPassword -length 13

		Generate password with length 13

	.LINK
		https://github.com/ripev/PowerShell/
#>
	param(
		[int]$length = 20,
		$characters ='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890~![]%^*-+=:.?_'
	)
	# select random characters
	$random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
	# output random pwd
	$private:ofs=""
	$pass = [String]$characters[$random]
	$pass
	# send pass to clipboard
	$pass|clip
}

Function Pause {
<#
	.SYNOPSIS
		Pause scripting

	.DESCRIPTION
		Pause scripting with message and waiting user interacting

	.PARAMETER message
		Set message to display. Default is "Press any key..."

	.EXAMPLE
		Pause

		Pause script

	.LINK
		https://github.com/ripev/PowerShell/
#>
    param ($message = "Press any key...")

    # Check if running Powershell ISE
    if ($psISE)
    {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("$message")
    }
    else
    {
        Write-Host "$message" -ForegroundColor Yellow
        $x = $host.ui.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

Function Get-NotStartedSVCs {
<#
	.SYNOPSIS
		Shows not started services

	.DESCRIPTION
		Shows services that not started but have startup type Automatic on localhost or selected server

	.PARAMETER srv
		Get not started servives on selected server

	.EXAMPLE
		Get-NotStartedSVCs

		Get not started services on localmachine

	.EXAMPLE
		Get-NotStartedSVCs -srv huston

		Get not started services on 'huston' server

	.LINK
		https://github.com/ripev/PowerShell/
#>
    param ($srv = "localhost")
    Get-Service -ComputerName $srv | Where-Object {$_.starttype -match "Automatic" -and $_.status -ne "Running"}
}

Function Get-RandomName {
<#
	.SYNOPSIS
		Generating random name

	.DESCRIPTION
		Generating random name with default length 20 or selected

	.PARAMETER length
		Integer parameter shows whith password length should be

	.EXAMPLE
		Get-RandomName

		Generate random name with length 20

	.EXAMPLE
		Get-RandomName -lengtn 40

		Generate random name with length 40
	.LINK
		https://github.com/ripev/PowerShell/
#>
	param(
		[int]$length = 20,$characters ='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789()=+_-'
	)
	$random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
	$private:ofs=""
	[String]$characters[$random]
}

Function Invoke-ABTPSScript {
<#
	.SYNOPSIS
		Run script from ABT source

	.DESCRIPTION
		Get scrip content from ABT site and execute

	.PARAMETER name
		Set script name parameter, wich should be executed

	.EXAMPLE
		Invoke-ABTPSScript test

		Download and execute script from link https://avicom.ru/uploader/ps1/test.ps1

	.LINK
		https://github.com/ripev/PowerShell/
#>
    Param ([Parameter(Mandatory=$true,Position=1)][String]$name)
    $url = "https://avicom.ru/uploader/ps1/" + $name + ".ps1"
	Invoke-Expression ((new-object net.webclient).DownloadString("$url"))
}

Function Invoke-DCsCommand {
<#
	.SYNOPSIS
		Invoke command on DC computers

	.DESCRIPTION
		Can be used with predefined credentials

	.EXAMPLE
		Invoke-DCsCommand -Command "Get-LocalDisk"

		Authorize and run command Get-LocalDisk on dc0[1-5]

	.EXAMPLE
		$cred = Get-Credential "User.Name"
		Invoke-DCsCommand -Credential $cred -Command "Get-LocalDisk"

		Authorize and run command Get-LocalDisk on dc0[1-5]
	
	.LINK
		https://github.com/ripev/PowerShell/
#>
	Param(
		[Parameter(Mandatory=$true,Position=0)] [String] $Command,
		[Parameter(Mandatory=$false,Position=1)] [Alias("Cred")] [PSCredential] $Credential,
		[switch] $All
	)
	if ($Credential -eq $null) {$Credential = Get-DCCredential}
	if ($All) {
		$srvs = "dc01.projectmate.ru","dc02.projectmate.ru","dc03.projectmate.ru","dc04.projectmate.ru","dc05.projectmate.ru","dc06.projectmate.ru"
	} else {
		$srvs = "dc01.projectmate.ru","dc02.projectmate.ru","dc03.projectmate.ru","dc05.projectmate.ru","dc06.projectmate.ru"
	}
	$Script = [Scriptblock]::Create($Command)
	foreach ($srv in $srvs) {
		"`n Executing command`t" | Write-Host -NoNewline -ForegroundColor Gray
		"'$Command'" | Write-Host -ForegroundColor Yellow
		" on " | Write-Host -ForegroundColor Gray -NoNewline
		"$srv`n" | Write-Host -ForegroundColor DarkCyan
		Invoke-Command -ComputerName $srv -Credential $Credential -UseSSL -ScriptBlock $Script
	}
}

Function Connect-Remote {
<#
	.SYNOPSIS
		Connect to SSL RemotePS

	.DESCRIPTION
		Alias for 'Enter-PSSession -ComputerName $srv -UseSSL -Credential $Credential' command

	.PARAMETER srv
		Server address to connect

	.PARAMETER credential
		User credential

	.EXAMPLE
		Connect-Remote -srv huston.com

		Connect remote powershell to huston.com server with current user credential

	.EXAMPLE
		Connect-Remote -srv huston.com -credential (Get-Credential 'vasya.pupkin')

		Get not started services on 'huston' server with requesting login/password for vasya.pupkin

	.LINK
		https://github.com/ripev/PowerShell/
#>
    param (
		[Parameter(Mandatory=$true,Position=0)] [ValidateNotNullOrEmpty()] [string] $srv,
		[Parameter(Mandatory=$false,Position=1)] [Alias("Cred")] [PSCredential] $Credential
	)
	if ($Credential -eq $null) {$Credential = Get-DCCredential}
	Enter-PSSession -ComputerName $srv -UseSSL -Credential $Credential
}

Function Get-File {
<#
	.SYNOPSIS
		Download file from URL

	.DESCRIPTION
		Using BitsTransfer or (new-object net.webclient).DownloadFile applets

	.PARAMETER name
		Use url for download file to current folder

	.EXAMPLE
		Get-File http://download.ru/example_file.zip

		Download file example_file.zip from url to current folder with example_file.zip name with net.webclient

	.EXAMPLE
		Get-File http://download.ru/example_file.zip -overwrite

		Download file example_file.zip from url to current folder and overwrite local file if exists

	.EXAMPLE
		Get-File http://download.ru/example_file.zip -bits

		Download file example_file.zip from url to current folder with BitsTransfer (display progress indicator)

	.LINK
		https://github.com/ripev/PowerShell/
#>
	Param(
		[Parameter(Mandatory=$true,Position=0)][String]$url,
		[Parameter(Mandatory=$false,Position=1)][switch]$OverWrite,
		[Parameter(Mandatory=$false,Position=2)][switch]$bits
	)
	$filename = Split-Path -leaf $url
	$location = (Get-Location).Path
	$file = "$location\$filename"
	if ($OverWrite) {Remove-Item $file -Force -ErrorAction SilentlyContinue}
	if ((Test-Path $file) -eq "True") {
		Write-Host "File " -NoNewline
		Write-Host "'$filename'" -f Cyan -NoNewline
		Write-Host " exists at path: " -NoNewline
		Write-Host "'$location'" -f Cyan
		Write-Host "Overwrite?" -f Red
		Write-Host "[y] Yes or " -NoNewline
		Write-Host "[N] No"  -f Yellow -NoNewline
		Write-Host " (Default is [N]):" -NoNewline
		$OverwriteReq = Read-Host
		if ($OverwriteReq -eq "Y") {Remove-Item $file -Force}
		else {Write-Host "Cannot overwrite file, use -overwrite switch instead!" -ForegroundColor DarkRed;Break}
	}
	if ($bits) {
		Start-BitsTransfer $url -DisplayName "Downloading" -Description $url
	} else {
		(new-object net.webclient).DownloadFile("$url","$file")
	}
}

Function Set-MAAAliases {
<#
	.SYNOPSIS
		Set aliases

	.LINK
		https://github.com/ripev/PowerShell/
#>
	$AliasPath = (Get-Variable profile).Value
	$PresentAliases = Get-Content $AliasPath
	[array]$Aliases = 'Set-Alias "cr" Connect-Remote'
	$Aliases += 'Set-Alias "maav" Get-MAAPSModuleVerions'
	foreach ($Alias in $Aliases) {
		if ($PresentAliases -notcontains $Alias) {
			Write-Output $Alias | Out-File $AliasPath -Append
		}
	}
}

Function Get-StoppedAppPools {
<#
	.SYNOPSIS
		Get stopped IIS AppPools

	.LINK
        https://github.com/ripev/PowerShell/
#>
	if ((Test-Admin) -eq $false) {
		Output "Please run scrip with Admin rignts" -color Red
		Pause "press any key to exit";Break
	}

	$LoadedModules = Get-Module
	$IsModuleLoaded = $false
	foreach ($LoadedModule in $LoadedModules) {
	if ($Module.Name -like 'WebAdministration') {
		$IsModuleLoaded = $True}}
	if ($IsModuleLoaded -eq $False) {
		Import-Module WebAdministration}
	Get-ChildItem IIS:\AppPools\ | Where-Object {$_.state -ne "started"}
}

Function Get-WAS7daysErrors {
<#
	.SYNOPSIS
		Get eventlog error for ASP.NET for last 7 days

	.LINK
		https://github.com/ripev/PowerShell/
#>
	Get-EventLog -LogName system -After ((Get-Date).AddDays(-7)) | Where-Object {$_.source -eq "WAS" -and $_.EntryType -ne "Information"}
}

Function Test-SSL {
<#
	.SYNOPSIS
		Check-SSL.ps1 - Gets SSL certificate expiration date
	.DESCRIPTION
		Check-SSL.ps1 - Gets SSL certificate expiration date and send an email alert if a defined threshold is exceeded.
	.PARAMETER WebsiteURL
		Defines the URL of the SSL certificate to check
		Mandatory parameter
		No default value.
	.PARAMETER WebsitePort
		Defines the website port of the SSL certificate to check
		Default is 443.
	.PARAMETER CommonName
		Defines the CommonName (CN) of the SSL certificate to check
		Default is the value of the WebsiteURL parameter.
	.PARAMETER Threshold
		Defines the threshold (in days). If the SSL certificate expiration date exceeded the threshold, an email alert is sent.
		Default is 15.
	.NOTES
		File Name   : Check-SSL.ps1
		Author      : Fabrice ZERROUKI - fabricezerrouki@hotmail.com
	.LINK
		http://www.zerrouki.com/checkssl/
	.EXAMPLE
		PS D:\> .\Check-SSL.ps1 -WebsiteURL secure.zerrouki.com -Threshold 30
		Performs a check of the expiration date for the SSL certificate that secures the website http://secure.zerrouki.com. If the certificate expires in less than 30 days, an email alert is sent.
#>
	Param(
		[Parameter(Mandatory=$true,Position=0,HelpMessage="IP address or hostname to check")][string]$WebsiteURL,
		[Parameter(Position=1,HelpMessage="The number of days after which an alert should be sent.")][int]$Threshold=15,
		[Parameter(Position=2,HelpMessage="TCP port number that SSL application is listening on")][int]$WebsitePort=443,
		[Parameter(Position=3)][switch]$MailSend,
		[Parameter(HelpMessage="CommonName (CN) on certificate")][string]$CommonName=$WebsiteURL
	)
	$Error.Clear()
	$MailTo="andrey.makovetsky@avicom.ru"
	$MailFrom="notifications@avicom.ru"
	$SmtpServer="localmail.abt.local"
	Try {
		$Conn = New-Object System.Net.Sockets.TcpClient($WebsiteURL,$WebsitePort) 
  
		Try {
			$Stream = New-Object System.Net.Security.SslStream($Conn.GetStream())
			$Stream.AuthenticateAsClient($CommonName) 
			$Cert = $Stream.Get_RemoteCertificate()
			$ValidTo = [datetime]::Parse($Cert.GetExpirationDatestring())
			Write-Host "`nConnection Successfull" -ForegroundColor DarkGreen
			Write-Host "Website: $WebsiteURL"
			$ValidDays = $($ValidTo - [datetime]::Now).Days
			if ($ValidDays -lt $Threshold) {
				Write-Host "`nStatus: Warning (Expires in $ValidDays days)" -ForegroundColor Yellow
				Write-Host "CertExpiration: $ValidTo`n" -ForegroundColor Yellow
				try {
					$MailSubject="$WebsiteURL - SSL certificate will expire in $ValidDays days"
					$MailBody=@"
						<html><span style='font-family: Tahoma; font-size: 12px;' >Hi,<br />
						<br />
						the SSL certificate for the website "$WebsiteURL" will expire in $ValidDays days. You should conserder renewing it.<br />
						<br />
						----------------------------------------------------------------------------</span><br />
						<span style='font-family: Tahoma; font-size: 10px;' >This is an automatically generated email, please do not reply.<br />&nbsp;<br /></span></html>
"@
					if ($MailSendOption) {
						Send-MailMessage -To $MailTo -Subject $MailSubject -From $MailFrom -SmtpServer $SmtpServer -Priority High -BodyAsHtml $MailBody -ErrorAction Stop
					}
				}    	
				catch {
					Write-Host "Cannot send email with message:" -ForegroundColor DarkGray
					Write-Host "$($_.Exception.Message)" -ForegroundColor Red
				}
			} else {
				Write-Host "`nStatus: OK" -ForegroundColor DarkGreen
				Write-Host "CertExpiration: $ValidTo`n" -ForegroundColor DarkGreen
			}
		}
		Catch { Throw $_ }
		Finally { $Conn.close() }
		}
	Catch {
			Write-Host "`nError occurred connecting to $($WebsiteURL)" -ForegroundColor Yellow
			Write-Host "Website: $WebsiteURL"
			Write-Host "Status:" $_.exception.innerexception.message -ForegroundColor Yellow
			Write-Host ""
	}
}

Function Get-CompInfo {
<#
	.SYNOPSIS
		Get hardware invormation

	.DESCRIPTION
		Show CPU and RAM information

	.LINK
		https://github.com/ripev/PowerShell/
#>
	param (
		[Parameter(Mandatory=$false,Position=0,ValueFromPipeline=$true)]
			[string] $Name = "localhost"
	)
	$Output=@()
	$CPUInfo = Get-WmiObject Win32_Processor -ComputerName $Name
	$OSInfo = Get-WmiObject Win32_OperatingSystem -ComputerName $Name
	$OSTotalVirtualMemory = [math]::round($OSInfo.TotalVirtualMemorySize / 1MB, 2)
	$OSTotalVisibleMemory = [math]::round(($OSInfo.TotalVisibleMemorySize / 1MB), 2)
	$PhysicalMemory = Get-WmiObject CIM_PhysicalMemory -ComputerName $Name | Measure-Object -Property capacity -Sum | % { [Math]::Round(($_.sum / 1GB), 2) }
	[int]$CPUCount = "1"
	if ($CPUInfo.Count -ge "2") {
		$CPUCount = $CPUInfo.Count
		$CPUInfo = $CPUInfo[0]
	}
	$AvailableCores = $CPUCount * $CPUInfo.NumberOfLogicalProcessors
	$OutputItem = New-Object Object
	$OutputItem | Add-Member NoteProperty "ServerName" -value $CPUInfo.SystemName
	$OutputItem | Add-Member NoteProperty "Processor" -value $CPUInfo.Name
	$OutputItem | Add-Member NoteProperty "Model" -value $CPUInfo.Description
	$OutputItem | Add-Member NoteProperty "Manufacturer" -value $CPUInfo.Manufacturer
	$OutputItem | Add-Member NoteProperty "ProcessorCount" -value $CPUCount
	$OutputItem | Add-Member NoteProperty "PhysicalCores" -value $CPUInfo.NumberOfCores
	$OutputItem | Add-Member NoteProperty "LogicalCores" -value $CPUInfo.NumberOfLogicalProcessors
	$OutputItem | Add-Member NoteProperty "AvailableCores" -value $AvailableCores
	$OutputItem | Add-Member NoteProperty "CPU_L2CacheSize" -value $CPUInfo.L2CacheSize
	$OutputItem | Add-Member NoteProperty "CPU_L3CacheSize" -value $CPUInfo.L3CacheSize
	#$OutputItem | Add-Member NoteProperty "Sockets" -value $CPUInfo.SocketDesignation
	$OutputItem | Add-Member NoteProperty "OS_Name" -value $OSInfo.Caption
	$OutputItem | Add-Member NoteProperty "OS_Version" -value $OSInfo.Version
	$OutputItem | Add-Member NoteProperty "TotalPhysical_Memory_GB" -value $PhysicalMemory
	$OutputItem | Add-Member NoteProperty "TotalVirtual_Memory_MB" -value $OSTotalVirtualMemory
	$OutputItem | Add-Member NoteProperty "TotalVisable_Memory_MB" -value $OSTotalVisibleMemory
	$Output += $OutputItem
	$Output
}