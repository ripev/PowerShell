#iex ((new-object net.webclient).DownloadString('https://raw.githubusercontent.com/ripev/PowerShell/master/MAAPSModule/MAAPSModuleInstall.ps1'))
<# Modules installation script
01.03.2017 andrey@makovetsky.me
#>

Function Get-RandomName {
	param(
		[int]$length = 20,$characters ='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789()=+_-'
	)
	$random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
	$private:ofs=""
	[String]$characters[$random]
}

$MAAPSModulePath = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\MAAPSModule"
$MAAPSModuleURLManifest = "https://raw.githubusercontent.com/ripev/PowerShell/master/MAAPSModule/MAAPSModule.psd1"
$MAAPSModuleURL = "https://raw.githubusercontent.com/ripev/PowerShell/master/MAAPSModule/MAAPSModule.psm1"
$MAAPSModuleURLManifestDownloaded = (new-object net.webclient).DownloadString($MAAPSModuleURLManifest)
$MAAPSModuleURLDownloaded = (new-object net.webclient).DownloadString($MAAPSModuleURL)

$RandomNameString = Get-RandomName
$psd1temp = $env:TEMP + "\" + $RandomNameString + ".psd1"
$psm1temp = $env:TEMP + "\" + $RandomNameString + ".psm1"

Write-Output $MAAPSModuleURLManifestDownloaded | Out-File $psd1temp -Encoding unicode
Write-Output $MAAPSModuleURLDownloaded | Out-File $psm1temp -Encoding utf8

if ((Test-Path $MAAPSModulePath) -ne $true) {
    New-Item $MAAPSModulePath -ItemType Directory
    Copy-Item "$psd1temp" "$MAAPSModulePath\MAAPSModule.psd1" -Force
    Copy-Item "$psm1temp" "$MAAPSModulePath\MAAPSModule.psm1" -Force
} else {
    $MAAPSModuleENV = Get-Module -ListAvailable | where {$_.Name -eq "MAAPSModule"}
    $LocalVersion = $MAAPSModuleENV.Version
    $InternetVersion = (Test-ModuleManifest $psd1temp).Version
    if ($LocalVersion -lt $InternetVersion) {
        Copy-Item "$psd1temp" "$MAAPSModulePath\MAAPSModule.psd1" -Force
        Copy-Item "$psm1temp" "$MAAPSModulePath\MAAPSModule.psm1" -Force
    } else {
        Write-Host "Version of localinstalled modules is equal." -f DarkCyan
        Write-Host "Upgrade files from web?" -f Cyan
        Write-Host "[Y] Yes" -f Yellow -NoNewline
        Write-Host " or [n] No (Default is [Y]):" -NoNewline
        $UpgradeSwith = Read-Host
        if ($UpgradeSwith -ne "n") {
            Copy-Item "$psd1temp" "$MAAPSModulePath\MAAPSModule.psd1" -Force
            Copy-Item "$psm1temp" "$MAAPSModulePath\MAAPSModule.psm1" -Force
        }
    }
}
Remove-Item $psd1temp -Force
Remove-Item $psm1temp -Force