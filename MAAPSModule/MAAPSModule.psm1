$MAAPSModulePSD1url = "https://raw.githubusercontent.com/ripev/PowerShell/master/MAAPSModule/MAAPSModule.psd1"
$MAAPSModulePSM1url = "https://raw.githubusercontent.com/ripev/PowerShell/master/MAAPSModule/MAAPSModule.psm1"

Function Get-MAAPSModuleInternetVersion {
<#
  .SYNOPSIS
    Get current MAAPSModule version from Github

  .LINK
    https://github.com/ripev/PowerShell/
#>
  #TLS
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $MAAPSModulePSD1urlDownloaded = (new-object net.webclient).DownloadString($MAAPSModulePSD1url)
  $MAAPSModulePSM1urlDownloaded = (new-object net.webclient).DownloadString($MAAPSModulePSM1url)
  $RandomNameString = Get-RandomName
  $temp = $MAAPSModulePSD1urlDownloaded
  $MAAPSModulePSD1urlDownloaded = $MAAPSModulePSD1urlDownloaded.Replace(".\MAAPSModule.psm1",".\$($RandomNameString).psm1")
  $psd1temp = $env:TEMP + "\" + $RandomNameString + ".psd1"
  $psm1temp = $env:TEMP + "\" + $RandomNameString + ".psm1"
  Write-Output $MAAPSModulePSD1urlDownloaded | Out-File $psd1temp -Encoding unicode
  Write-Output $MAAPSModulePSM1urlDownloaded | Out-File $psm1temp -Encoding utf8
  $Output=@()
  $OutputItem = New-Object Object
  $OutputItem | Add-Member NoteProperty "Version" (Test-ModuleManifest $psd1temp).Version
  $OutputItem | Add-Member NoteProperty "psdpath" $psd1temp
  $OutputItem | Add-Member NoteProperty "psmpath" $psm1temp
  $Output += $OutputItem
  $Output
  Write-Output $temp | Out-File $psd1temp -Encoding unicode
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
  Write-Host "$($InternetVersion.Major).$($InternetVersion.Minor).$($InternetVersion.Build)" -ForegroundColor Green
  $LocalVersion = Get-MAAPSModuleLocalVersion
  Write-Host "Local version of modules is:`t" -ForegroundColor Yellow -NoNewline
  Write-Host "$($LocalVersion.Major).$($LocalVersion.Minor).$($LocalVersion.Build)" -ForegroundColor Green
  if ($LocalVersion -ne $InternetVersion) {
    Write-Output "`nLocal and Internet versions is mismatch. You should update local version"
  }
}

Function Get-MAACommands {
<#
  .SYNOPSIS
    Show MAA module commands with aliases

  .DESCRIPTION
    Alias for get-command from MAAPSModule

  .LINK
    https://github.com/ripev/PowerShell/
#>
  [array] $allAliases = Get-Alias | Where-Object {$_.Source -eq "MAAPSmodule"}
  Get-Command -Module MAAPSModule | Select-Object `
    @{l="Command";e={
      if ($psISE) {
        "$($_.Name)"
      } else {
        $e = [char]27
        $color = "93"
        "$e[${color}m$($_.Name)${e}[0m"
      }
    }},`
    @{l="Synopsis";e={$((Get-Help $_.Name).Synopsis)}},`
    @{l="Alias";e={
      $name=$_.Name;
      $alias = $allAliases | Where-Object {$_.DisplayName -match $name} | Select-Object -First 1
      if ($psISE) {
        "$($alias)"
      } else {
        $e = [char]27
        $color = "36"
        "$e[${color}m$($alias)${e}[0m"
      }
    }} | Format-Table -AutoSize
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
        Write-Host "$($LocalVersion.Major).$($LocalVersion.Minor).$($LocalVersion.Build)" -ForegroundColor Yellow -NoNewline
        Write-Host "' to '" -ForegroundColor Gray -NoNewline
        Write-Host "$($InternetVersion.Major).$($InternetVersion.Minor).$($InternetVersion.Build)" -ForegroundColor Yellow -NoNewline
        Write-Host "'" -ForegroundColor Gray
      }
      Copy-Item "$psd1temp" "$MAAPSModulePath\MAAPSModule.psd1" -Force -ErrorAction Stop
      Copy-Item "$psm1temp" "$MAAPSModulePath\MAAPSModule.psm1" -Force -ErrorAction Stop
      Write-Host "Modules updated successfully. Reload PowerShell to apply changes." -ForegroundColor DarkCyan
    }
    catch {
      Write-Host "Copy error:" -ForegroundColor DarkGray
      Show-CustomError
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
  #TLS
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-Expression ((new-object net.webclient).DownloadString('https://raw.githubusercontent.com/ripev/PowerShell/master/MAAFunctions/MAAFunctionsInstall.ps1'))
}

Function Get-StoredCredential {
<#
  .SYNOPSIS
    Get secured sctring from file
  .DESCRIPTION
    Subfunction used in connect functions

  .LINK
    https://github.com/ripev/PowerShell/
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$false)]
      [string]$username = $env:USERNAME
  )
  $CredFilePath = "$($env:USERPROFILE)\.ssh\creds\${username}_$($env:COMPUTERNAME).cred"
  if ((Test-Path $CredFilePath -ErrorAction SilentlyContinue) -eq $false) {
    Output -str "File with credentials not found at '$($env:USERPROFILE)\.ssh\creds\'" -color Red
    Output -str "You can create credential file with folowing command:" -color Gray
    Output -str '$Credential = Get-Credential' -color Yellow
    Output -str '$Credential.Password | ConvertFrom-SecureString | Out-File -PSPath "$($env:USERPROFILE)\.ssh\creds\$($Credential.UserName)_$($env:COMPUTERNAME).cred"'
  } else {
    $CredFile = Get-Item $CredFilePath
    try {
      $PwdSecureString = Get-Content $CredFile | ConvertTo-SecureString -ErrorAction Stop
      New-Object System.Management.Automation.PSCredential -ArgumentList $username, $PwdSecureString
    } catch {
      Output "Probably file created in other user session." -color Gray
      Output "Recreate file with following command:" -color Gray
      Output -str '$Credential = Get-Credential' -color Yellow
      Output -str '$Credential.Password | ConvertFrom-SecureString | Out-File -PSPath "$($env:USERPROFILE)\.ssh\creds\$($Credential.UserName)_$($env:COMPUTERNAME).cred"'
    }
  }
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
  Where-Object {$_.DriveType -eq 3 -and $_.DriveLetter} | `
  Select-Object `
    DriveLetter,Label,FileSystem,`
  @{l="FreeSpace";e={"$([math]::Round(($_.FreeSpace / 1GB), 2)) GB"}},`
  @{l="Free %";e={"$([math]::Round(($_.FreeSpace / $_.Capacity * 100), 2)) %"}},`
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
      [String[]] $instance,
    [parameter(Mandatory=$false)]
      [Switch] $all
  )
  if(!$instance){$instance = "localhost"}
  $location = Get-Location
  [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | Out-Null
  $server = New-Object ('Microsoft.SqlServer.Management.Smo.Server') "$instance"
  if ($server.status -ne "Online") {
    Write-Host "Cannot connect to '$($instance)'" -ForegroundColor Red
    Break
  }
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
    Try {
      if ((Get-Command Invoke-Sqlcmd -ErrorAction SilentlyContinue).count -gt 0) {
        $dbinfo = Invoke-Sqlcmd -ServerInstance "$instance" -Query $query -ErrorAction Stop
      } else {
        if ((Get-Command Invoke-SQLCustomScript -ErrorAction SilentlyContinue).count -eq 1) {
          $dbinfo = Invoke-SQLCustomScript -SQLInstance "$instance" -SQLDBName "master" -SQLScript $query -ErrorAction Stop
        } else {
          Write-Host "No SQL commands find. Try to install Management Studio or MAAFunctions." -ForegroundColor DarkRed
          Break
        }
      }
    } Catch {
      Show-CustomError
      Break
    }
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
    $host.ui.RawUI.ReadKey("NoEcho,IncludeKeyDown")
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
  $GetServicesCmd = {
    Get-Service | Where-Object {$_.starttype -match "Automatic" -and $_.status -ne "Running"}
  }
  if ($srv -eq "localhost") {
    Invoke-Command -ScriptBlock $GetServicesCmd
  } else {
    Invoke-Command -ScriptBlock $GetServicesCmd -ComputerName $srv
  }
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

Function Invoke-ComDepCommand {
<#
  .SYNOPSIS
    Invoke command on ComDep servers

  .DESCRIPTION
    Invoke command on ComDep servers

  .EXAMPLE
    Invoke-ComDepCommand -Command "Get-LocalDisk"

    Authorize and run command Get-LocalDisk on ComDep servers

  .NOTES
    Alias: icc

  .LINK
    https://github.com/ripev/PowerShell/
#>
  Param(
    [Parameter(Mandatory=$true,Position=0)] [String] $Command,
    [Parameter(Mandatory=$false,Position=1)] [switch] $admin
  )
  $srvs = `
    "tw-com1",
    "tw-com4",
    "spb-pw-com1",
    "spb-s-comdep",
    "pw-com2",
    "pw-pos-srv1",
    "pw-pos-srv2",
    "pw-fin3",
    "pw-fin4",
    "pw-workki02"
  $JobItems=@();
  $JobDatePreffix = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
  $i=30;Write-Host ""("+"*$i)"`n  Starting jobs on all servers`n"("+"*$i) -ForegroundColor Cyan
  if ($admin) {
    $adminCred = Get-StoredCredential $($env:USERNAME).replace('.', '_')
  }
  foreach ($srv in $srvs) {
    $remoteCmd = {
      $srv = $args[0]
      $Command = $args[1]
      $creds = $args[2]
      $Script = [Scriptblock]::Create($Command)
      if ($creds) {
        Invoke-Command -ComputerName $srv -ScriptBlock $Script -Credential $creds
      } else {
        Invoke-Command -ComputerName $srv -ScriptBlock $Script
      }
    }
    $jobName = "$($JobDatePreffix)_$($srv)"
    if ($admin) {
      Start-Job -Name $jobName -ScriptBlock $remoteCmd -ArgumentList $srv,$Command,$adminCred | Out-Null
    } else {
      Start-Job -Name $jobName -ScriptBlock $remoteCmd -ArgumentList $srv,$Command | Out-Null
    }
    $JobItems += $jobName
  }
  
  while ($JobItems.Length -gt 0) {
    $jobs = Get-Job | Where-Object {$_.State -eq "Completed"}
    if ($jobs.count -gt 0) {
      foreach ($job in $jobs) {
        if ($JobItems -match $job.Name) {
          [string] $matchRegex = "^(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_)(.*)$"
          if ($job.Name -match $matchRegex) {
            [string] $computerName = $Matches[2]
          } else {
            [string] $computerName = $job.Name
          }
          Write-Host "`nExecution on '" -f Gray -NoNewLine
          Write-Host $computerName -f Cyan -NoNewLine
          Write-Host "' results:`n" -f Gray
          Receive-Job -Name $job.Name
          Remove-Job -Name $job.Name -Force
          $NewJobItems = $JobItems | Where-Object {$_ -ne $job.name}
          $JobItems = $NewJobItems
          Remove-Variable -Name NewJobItems -Force -ErrorAction SilentlyContinue
        }
      }
    }
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
  [CmdletBinding(DefaultParameterSetName='creds')]
  param (
    [Parameter(Mandatory=$true,Position=0)] [ValidateNotNullOrEmpty()] [string] $srv,
    [Parameter(ParameterSetName='creds',Mandatory=$false,Position=1)] [Alias("Cred")] [PSCredential] $Credential,
    [Parameter(ParameterSetName='admin',Mandatory=$false,Position=1)] [switch] $admin
  )
  if ($admin) {
    $Credential = Get-StoredCredential $($env:USERNAME).replace('.', '_')
  } elseif ($null -eq $Credential) {
    $Credential = Get-StoredCredential
  }
  Enter-PSSession -ComputerName $srv -Credential $Credential
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
    Write-Host "[N] No" -f Yellow -NoNewline
    Write-Host " (Default is [N]):" -NoNewline
    $OverwriteReq = Read-Host
    if ($OverwriteReq -eq "Y") {Remove-Item $file -Force}
    else {Write-Host "Cannot overwrite file, use -overwrite switch instead!" -ForegroundColor DarkRed;Break}
  }
  if ($bits) {
    Start-BitsTransfer $url -DisplayName "Downloading" -Description $url
  } else {
    #TLS
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    (new-object net.webclient).DownloadFile("$url","$file")
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
    Gets SSL certificate expiration date
  .DESCRIPTION
    Gets SSL certificate expiration date and send an email alert if a defined threshold is exceeded.
  .PARAMETER WebsiteURL
    Defines the URL of the SSL certificate to check
    Mandatory parameter
    No default value.
  .PARAMETER WebsitePort
    Defines the website port of the SSL certificate to check
    Default is 443.
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
    [Parameter(Position=1,HelpMessage="TCP port number that SSL application is listening on")][int]$WebsitePort=443
  )
  [datetime] $today = Get-Date
  Try {
    $Conn = New-Object System.Net.Sockets.TcpClient($WebsiteURL,$WebsitePort)
    Try {
      $Stream = New-Object System.Net.Security.SslStream($Conn.GetStream())
      $Stream.AuthenticateAsClient($WebsiteURL)
      $Cert = $Stream.Get_RemoteCertificate()
      $ValidTo = [datetime]::Parse($Cert.GetExpirationDatestring())
      $out = New-Object System.Object
      $out | Add-Member NoteProperty -Name "site"          -Value $WebsiteURL
      $out | Add-Member NoteProperty -Name "expirationDay" -Value $ValidTo
      $out | Add-Member NoteProperty -Name "daysToExpire"  -Value $($ValidTo - $today).Days
      Return $out
    }
    Catch { Throw $_ }
    Finally { $Conn.close() }
  }
  Catch {
    Write-Host "Error occurred connecting to $($WebsiteURL)" -ForegroundColor Yellow
    Write-Host "Website: $($WebsiteURL)"
    Write-Host "Status:" $_.exception.innerexception.message -ForegroundColor Yellow
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
  $PhysicalMemory = Get-WmiObject CIM_PhysicalMemory -ComputerName $Name | Measure-Object -Property capacity -Sum | ForEach-Object { [Math]::Round(($_.sum / 1GB), 2) }
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

function New-IsoFile {
<#
  .Synopsis
  Creates a new .iso file
  .Description
  The New-IsoFile cmdlet creates a new .iso file containing content from chosen folders
  .Example
  New-IsoFile "c:\tools","c:Downloads\utils"
  This command creates a .iso file in $env:temp folder (default location) that contains c:\tools and c:\downloads\utils folders. The folders themselves are included at the root of the .iso image.
  .Example
  New-IsoFile -FromClipboard -Verbose
  Before running this command, select and copy (Ctrl-C) files/folders in Explorer first.
  .Example
  dir c:\WinPE | New-IsoFile -Path c:\temp\WinPE.iso -BootFile "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\efisys.bin" -Media DVDPLUSR -Title "WinPE"
  This command creates a bootable .iso file containing the content from c:\WinPE folder, but the folder itself isn't included. Boot file etfsboot.com can be found in Windows ADK. Refer to IMAPI_MEDIA_PHYSICAL_TYPE enumeration for possible media types: http://msdn.microsoft.com/en-us/library/windows/desktop/aa366217(v=vs.85).aspx
  .Link
  https://gallery.technet.microsoft.com/scriptcenter/New-ISOFile-function-a8deeffd
  .Notes
  NAME: New-IsoFile
  AUTHOR: Chris Wu
  LASTEDIT: 03/23/2016 14:46:50
#>
  [CmdletBinding(DefaultParameterSetName='Source')]
    Param(
      [parameter(Position=1,Mandatory=$true,ValueFromPipeline=$true, ParameterSetName='Source')]$Source,
      [parameter(Position=2)][string]$Path = "$env:temp\$((Get-Date).ToString('yyyyMMdd-HHmmss.ffff')).iso",
      [ValidateScript({Test-Path -LiteralPath $_ -PathType Leaf})][string]$BootFile = $null,
      [ValidateSet('CDR','CDRW','DVDRAM','DVDPLUSR','DVDPLUSRW','DVDPLUSR_DUALLAYER','DVDDASHR','DVDDASHRW','DVDDASHR_DUALLAYER','DISK','DVDPLUSRW_DUALLAYER','BDR','BDRE')][string] $Media = 'DVDPLUSRW_DUALLAYER',
      [string]$Title = (Get-Date).ToString("yyyyMMdd-HHmmss.ffff"),
      [switch]$Force,
      [parameter(ParameterSetName='Clipboard')][switch]$FromClipboard
  )

  Begin {
    ($cp = new-object System.CodeDom.Compiler.CompilerParameters).CompilerOptions = '/unsafe'
    if (!('ISOFile' -as [type])) {
      Add-Type -CompilerParameters $cp -TypeDefinition @'
public class ISOFile
{
  public unsafe static void Create(string Path, object Stream, int BlockSize, int TotalBlocks)
  {
    int bytes = 0;
    byte[] buf = new byte[BlockSize];
    var ptr = (System.IntPtr)(&bytes);
    var o = System.IO.File.OpenWrite(Path);
    var i = Stream as System.Runtime.InteropServices.ComTypes.IStream;

    if (o != null) {
      while (TotalBlocks-- > 0) {
        i.Read(buf, BlockSize, ptr); o.Write(buf, 0, bytes);
      }
      o.Flush(); o.Close();
    }
  }
}
'@
    }

    if ($BootFile) {
      if('BDR','BDRE' -contains $Media) { Write-Warning "Bootable image doesn't seem to work with media type $Media" }
      ($Stream = New-Object -ComObject ADODB.Stream -Property @{Type=1}).Open() # adFileTypeBinary
      $Stream.LoadFromFile((Get-Item -LiteralPath $BootFile).Fullname)
      ($Boot = New-Object -ComObject IMAPI2FS.BootOptions).AssignBootImage($Stream)
    }

    $MediaType = @('UNKNOWN','CDROM','CDR','CDRW','DVDROM','DVDRAM','DVDPLUSR','DVDPLUSRW','DVDPLUSR_DUALLAYER','DVDDASHR','DVDDASHRW','DVDDASHR_DUALLAYER','DISK','DVDPLUSRW_DUALLAYER','HDDVDROM','HDDVDR','HDDVDRAM','BDROM','BDR','BDRE')

    Write-Verbose -Message "Selected media type is $Media with value $($MediaType.IndexOf($Media))"
    ($Image = New-Object -com IMAPI2FS.MsftFileSystemImage -Property @{VolumeName=$Title}).ChooseImageDefaultsForMediaType($MediaType.IndexOf($Media))
    if (!($Target = New-Item -Path $Path -ItemType File -Force:$Force -ErrorAction SilentlyContinue)) { Write-Error -Message "Cannot create file $Path. Use -Force parameter to overwrite if the target file already exists."; break }
  }

  Process {
    if($FromClipboard) {
      if($PSVersionTable.PSVersion.Major -lt 5) { Write-Error -Message 'The -FromClipboard parameter is only supported on PowerShell v5 or higher'; break }
      $Source = Get-Clipboard -Format FileDropList
    }

    foreach($item in $Source) {
      if($item -isnot [System.IO.FileInfo] -and $item -isnot [System.IO.DirectoryInfo]) {
        $item = Get-Item -LiteralPath $item
      }

      if($item) {
        Write-Verbose -Message "Adding item to the target image: $($item.FullName)"
        try { $Image.Root.AddTree($item.FullName, $true) } catch { Write-Error -Message ($_.Exception.Message.Trim() + ' Try a different media type.') }
      }
    }
  }

  End {
    if ($Boot) { $Image.BootImageOptions=$Boot }
    $Result = $Image.CreateResultImage()
    [ISOFile]::Create($Target.FullName,$Result.ImageStream,$Result.BlockSize,$Result.TotalBlocks)
    Write-Verbose -Message "Target image ($($Target.FullName)) has been created"
    $Target
  }
}

function ConvertTo-Base64 {
<#
  .Synopsis
    Convert string to base64
#>
  param (
    [Parameter(ValueFromPipeline=$true)]
    [String] $inputString
  )
  $base64string = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($inputString))
  return $base64string
}

function ConvertFrom-Base64 {
<#
  .Synopsis
    Convert string from base64
#>
  param (
    [Parameter(ValueFromPipeline=$true)]
    [String] $inputString
  )
  $convertedString = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($inputString))
  return $convertedString
}

function Save-ScreenShot
{
  <#
    .Synopsis
      Create full screen shot
    .LINK
      https://gist.github.com/farag2/25747b927e76ccb24e23c6d0d25715ad
  #>
  Param([string]$Path)
  Try {
    if ($env:OneDrive) {
      [string] $rootPath = "$($env:OneDrive)\images\screenshots"
    } else {
      [string] $rootPath = "."
    }
    if (-not $Path) { $Path = $rootPath }
    IF (-not (Test-Path -Path $Path)) {
      $null = New-Item -Path $Path -ItemType Directory -Force
    }
  } Catch {           $Path = (Get-Location).Path }
  $FileName = "$(Get-Date -f yyyy-MM-dd_HHmmss).bmp"
  $File = "$Path\$FileName"
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing
  $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
  $Width = $Screen.Width
  $Height = $Screen.Height
  $Left = $Screen.Left
  $Top = $Screen.Top
  # Create bitmap using the top-left and bottom-right bounds
  $bitmap = New-Object System.Drawing.Bitmap $Width, $Height
  # Create Graphics object
  $graphic = [System.Drawing.Graphics]::FromImage($bitmap)
  # Capture screen
  $graphic.CopyFromScreen($Left, $Top, 0, 0, $bitmap.Size)
  $bitmap.Save($File)
}

Set-Alias -name cr Connect-Remote
Set-Alias -name svs Save-ScreenShot
Set-Alias -name icc Invoke-ComDepCommand
Set-Alias -name maac Get-MAACommands
Set-Alias -name maav Get-MAAPSModuleVerions
Set-Alias -name ssl Test-SSL
Set-Alias -name cfb ConvertFrom-Base64
Set-Alias -name ctb ConvertTo-Base64