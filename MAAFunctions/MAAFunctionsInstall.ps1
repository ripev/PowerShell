<#Most used functions installation
05.12.2017 andrey@makovetsky.me#>

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

Function Get-RandomName {
	param(
		[int]$length = 20,$characters ='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789()=+_-'
	)
	$random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
	$private:ofs=""
	[String]$characters[$random]
}

if ((Test-Admin) -eq $false) {Write-Host "Run PowerShell with admin rights!" -ForegroundColor Red;break}

$MAAFunctionsPath = "$($env:ProgramFiles)\WindowsPowerShell\Modules\MAAFunctions\"
if ((Test-Path $MAAFunctionsPath)) {Remove-Item $MAAFunctionsPath -Force -Recurse}
New-Item $MAAFunctionsPath -ItemType Directory | Out-Null
$MAAFunctionsPSDURL = "https://raw.githubusercontent.com/ripev/PowerShell/master/MAAFunctions/MAAFunctions.psd1"
$MAAFunctionsPSMURL = "https://raw.githubusercontent.com/ripev/PowerShell/master/MAAFunctions/MAAFunctions.psm1"
$MAAFunctionsPSDURLDownloaded = (new-object net.webclient).DownloadString($MAAFunctionsPSDURL)
$MAAFunctionsPSMURLDownloaded = (new-object net.webclient).DownloadString($MAAFunctionsPSMURL)
$MAAFunctionsPSD = "$($MAAFunctionsPath)MAAFunctions.psd1"
$MAAFunctionsPSM = "$($MAAFunctionsPath)MAAFunctions.psm1"
$MAAFunctionsPSDURLDownloaded | Out-File $MAAFunctionsPSD -Encoding utf8
$MAAFunctionsPSMURLDownloaded | Out-File $MAAFunctionsPSM -Encoding utf8