#region colors
if ($host.Version.Major -ge 5 -and -not ($env:JENKINS_HOME) ) {
  $Global:esc="$([char]27)"
  $Global:TXT_YELLOW="$($Global:esc)[33m"
  $Global:TXT_MAGENTA="$($Global:esc)[35m"
  $Global:TXT_RED="$($Global:esc)[31m"
  $Global:TXT_CLEAR="$($Global:esc)[0m"
} else {
  $Global:TXT_YELLOW=""
  $Global:TXT_MAGENTA=""
  $Global:TXT_RED=""
  $Global:TXT_CLEAR=""
}
#endregion
Function Get-MAAFunctions {
<#
  .SYNOPSIS
    Show MAA functions with aliases
  .LINK
    https://github.com/ripev/PowerShell/
#>
  [array] $allAliases = Get-Alias | Where-Object {$_.Source -eq "MAAPFunctions"}
  Get-Command -Module MAAFunctions | Select-Object `
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
Function Get-LoggedOnUser {
<#
  .SYNOPSIS
    Get list of logget users
#>
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
    Checko elevated execution
  .DESCRIPTION
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
    Native mssql scripting
  .DESCRIPTION
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
  [CmdletBinding()]
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
  #region parsing servername/port
  if ($SQLInstance -match "^(.*)(\,)(\d{1,5})") {
    $null = $SQLInstance -match "^(.*)(\,)(\d{1,5})"
    [string] $SQLServerName = $Matches[1]
    [int] $SQLServerPort = $Matches[3]
  } elseif ($SQLInstance -match "^(.*)(\\)(\D)") {
    [string] $SQLServerName = $Matches[1]
    [int] $SQLServerPort = 1433
  } else {
    [string] $SQLServerName = $SQLInstance
    [int] $SQLServerPort = 1433
  }
  #endregion parsing servername/port

  #region testing sqlserver connection available
  [int] $testCounter      = 0;
  [int] $maxTests         = 5;
  [bool] $serverAvailable = $false;
  while (-not $serverAvailable -and $testCounter -lt $maxTests) {
    $serverAvailable = Test-PortAvailable $SQLServerName $SQLServerPort 200
    $testCounter++
  }
  if ($serverAvailable) {
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
    Try {
      $SqlCmd = New-Object System.Data.SqlClient.SqlCommand
      $SqlCmd.CommandText = $SQLScript
      $SqlCmd.Connection = $SqlConnection
      $SqlCmd.CommandTimeout = $Timeout
      $SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
      $SqlAdapter.SelectCommand = $SqlCmd
      $DataSet = New-Object System.Data.DataSet
      $null = $SqlAdapter.Fill($DataSet)
      $SqlConnection.Close()
      Set-Location $StartLocation
      $DataSet.Tables[0]
    } Catch {
      Set-Location $StartLocation
      Show-CustomError
      if ($ErrorActionPreference -eq "Stop") { Exit 1 }
    }
  } else { Write-Warning "Connection to '$($SQLInstance)' cannot be established." }
  #endregion testing sqlserver connection available
}
Function New-CustomGuid {
<#
  .SYNOPSIS
    New-GUID like (if not present)
  .DESCRIPTION
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
function Test-PortAvailable ([string]$hostname,[int]$port,[int]$timeout) {
<#
  .SYNOPSIS
    Check port available
#>
  $client = New-Object System.Net.Sockets.TcpClient
  $null = $client.BeginConnect($hostname,$port,$null,$null)
  Start-Sleep -milliseconds $timeOut
  if ($client.Connected) { $connectionOpen = $true } else { $connectionOpen = $false }
  $client.Close()
  Return $connectionOpen
}
Function fileSizeOutput {
<#
  .SYNOPSIS
    Convert input integer to pretty TB/GB/MB/KB format
  .DESCRIPTION
    Returns (convert) size in format #.### TB/GB/MB/KB
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
  $isNegative = $Size -lt 0
  $Size = [math]::Abs($Size)
  if ($Size -ge 1099511627776) { # check that size in TB
    $result = ($($Size)/1099511627776).ToString("0.###") + " TB"
  } elseif ($Size -ge 1073741824) { # check that size in GB
    $result = ($($Size)/1073741824).ToString("0.###") + " GB"
  } elseif ($Size -ge 1048576) { # check that size in MB
    $result = ($($Size)/1048576).ToString("0.###") + " MB"
  } else { # check that size in KB
    $result = ($($Size)/1024).ToString("0.###") + " KB"
  }
  if ($isNegative) {
    $result = "-" + $result
  }
  return $result
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
    Return or outputs time duration in readable format
  .DESCRIPTION
    Return or outputs time duration in readable format
  .PARAMETER duration
    Input timespan to output
  .PARAMETER nColor
    Specify color for digits
  .PARAMETER sColor
    Specify color for strings
  .PARAMETER NoNewLine
    No new line after output
  .PARAMETER OutputToLine
    Outputs string, unlike return
  .EXAMPLE
    timeDurationOutput [timespan]$duration
    Return duration in '1 h 13 m 34 s' format
  .EXAMPLE
    timeDurationOutput [timespan]$duration -OutputToLine
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
      [Switch] $NoNewLine,
    [Parameter (Mandatory=$false)]
      [Switch] $OutputToLine
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
  $hoursWithoutDays = $duration.Hours
  $minutesWithoutHours = $duration.Minutes
  $secondsWithoutMinutes = $duration.Seconds
  $returnValue = $null;
  if ($OutputToLine) {
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
  } else {
    # Days output
    if ([math]::Round($duration.TotalDays) -gt 0) {
      $returnValue += "$([math]::Round($duration.TotalDays)) d"
      if ($hoursWithoutDays -gt 0 -or $minutesWithoutHours -gt 0 -or $secondsWithoutMinutes -gt 0) {
        $returnValue += " "
      }
    }
    # Hours output
    if ($duration.TotalHours -gt 0 -and $hoursWithoutDays -gt 0) {
      $returnValue += "$([math]::Round($duration.TotalHours % 24)) h"
      if ($minutesWithoutHours -gt 0 -or $secondsWithoutMinutes -gt 0) {
        $returnValue += " "
      }
    }
    # Minutes output
    if ($duration.TotalMinutes -gt 0 -and $minutesWithoutHours -gt 0) {
      $returnValue += "$($minutesWithoutHours) m"
      if ($secondsWithoutMinutes -gt 0) {
        $returnValue += " "
      }
    }
    # Seconds output
    if ($duration.TotalSeconds -gt 0 -and $secondsWithoutMinutes -gt 0) {
      $returnValue += "$($secondsWithoutMinutes) s"
    }
    $returnValue
  }
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
    Find like grep with color
  .DESCRIPTION
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
    528040 = [version]'4.8'
    528049 = [version]'4.8'
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
    return $factorial
  }
}
function Set-ColorExpressionOutput {
<#
  .SYNOPSIS
    Colorize expression output
#>
    # desription https://stackoverflow.com/questions/20705102/how-to-colorise-powershell-output-of-format-table
    # colors https://docs.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences#span-idtextformattingspanspan-idtextformattingspanspan-idtextformattingspantext-formatting
  param (
    [Parameter(Mandatory=$true,Position=0)]
      $data,
    [Parameter(Mandatory=$false,Position=1)]
            [ValidateSet ("black","red","green","yellow","blue","magenta","cyan","white","default")]
      [string] $color = "default"
  )
  switch ($color) {
        "black"   {$col=30;break}
        "red"     {$col=31;break}
        "green"   {$col=32;break}
        "yellow"  {$col=33;break}
        "blue"    {$col=34;break}
        "magenta" {$col=35;break}
        "cyan"    {$col=36;break}
        "white"   {$col=37;break}
        "default" {$col=39;break}
  }
  $e=[char]27
  "$e[${col}m$($data)${e}[0m"
}
function Clear-Spaces {
<#
  .Synopsis
    Cut first and last spaces
#>
  param(
    [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [string] $InputObject
  )
  Return $($InputObject -replace "\s+$","" -replace "^\s+","")
}

function ConvertFrom-LinuxTime {
<#
  .Synopsis
    Convert from linux time
  .Inputs
    [Int]
  .Outputs
    [datetime]
#>
  param ([int]$linuxTime)
  [datetime] $linuxStartTime = [datetime]::ParseExact("1970-01-01 00:00:00","yyyy-MM-dd HH:mm:ss",$null)
  Return $linuxStartTime.AddSeconds($linuxTime + (Get-TimeZone).BaseUtcOffset.TotalSeconds)
}
function ConvertTo-LinuxTime {
  <#
    .Synopsis
      Convert to linux time
    .Inputs
      [datetime]
    .Outputs
      [Int]
  #>
    param ([datetime]$datetime)
    $linuxTime = [int][double]::Parse((Get-Date -Date $datetime -UFormat %s))
    Return $linuxTime
}
function Invoke-FlashWindow {
<#
  .SYNOPSIS
    Flashes a window that has been hidden or minimized to the taskbar
  .DESCRIPTION
    Flashes a window that has been hidden or minimized to the taskbar
  .PARAMETER MainWindowHandle
    Handle of the window that will be set to flash
  .PARAMETER FlashRate
    The rate at which the window is to be flashed, in milliseconds.
    Default value is: 0 (Default cursor blink rate)
  .PARAMETER FlashCount
    The number of times to flash the window.
    Default value is: 2147483647
  .NOTES
    Name: Invoke-FlashWindow
    Author: Boe Prox
    Created: 26 AUG 2013
    Version History
        1.0 -- 26 AUG 2013 -- Boe Prox
            -Initial Creation
  .LINK
    https://learn-powershell.net/2013/08/26/make-a-window-flash-in-taskbar-using-powershell-and-pinvoke/
    http://pinvoke.net/default.aspx/user32/FlashWindowEx.html
    http://msdn.microsoft.com/en-us/library/windows/desktop/ms679347(v=vs.85).aspx
  .EXAMPLE
    Start-Sleep -Seconds 5; Get-Process -Id $PID | Invoke-FlashWindow
    #Minimize or take focus off of console
    Description
    -----------
    PowerShell console taskbar window will begin flashing. This will only work if the focus is taken
    off of the console, or it is minimized.
  .EXAMPLE
    Invoke-FlashWindow -MainWindowHandle 565298 -FlashRate 150 -FlashCount 10
    Description
    -----------
    Flashes the window of handle 565298 for a total of 10 cycles while blinking every 150 milliseconds.
#>
  [cmdletbinding()]
  Param (
    [parameter(ValueFromPipeline=$True,ValueFromPipeLineByPropertyName=$True)]
      [intptr]$MainWindowHandle,
    [parameter()]
      [int]$FlashRate = 0,
    [parameter()]
      [int]$FlashCount = ([int]::MaxValue)
  )
  Begin {        
    Try {
      $null = [Window]
    } Catch {
      Add-Type -TypeDefinition @"
        using System;
        using System.Collections.Generic;
        using System.Text;
        using System.Runtime.InteropServices;

        public class Window
        {
          [StructLayout(LayoutKind.Sequential)]
          public struct FLASHWINFO
          {
            public UInt32 cbSize;
            public IntPtr hwnd;
            public UInt32 dwFlags;
            public UInt32 uCount;
            public UInt32 dwTimeout;
          }

          //Stop flashing. The system restores the window to its original state. 
          const UInt32 FLASHW_STOP = 0;
          //Flash the window caption. 
          const UInt32 FLASHW_CAPTION = 1;
          //Flash the taskbar button. 
          const UInt32 FLASHW_TRAY = 2;
          //Flash both the window caption and taskbar button.
          //This is equivalent to setting the FLASHW_CAPTION | FLASHW_TRAY flags. 
          const UInt32 FLASHW_ALL = 3;
          //Flash continuously, until the FLASHW_STOP flag is set. 
          const UInt32 FLASHW_TIMER = 4;
          //Flash continuously until the window comes to the foreground. 
          const UInt32 FLASHW_TIMERNOFG = 12; 


          [DllImport("user32.dll")]
          [return: MarshalAs(UnmanagedType.Bool)]
          static extern bool FlashWindowEx(ref FLASHWINFO pwfi);

          public static bool FlashWindow(IntPtr handle, UInt32 timeout, UInt32 count)
          {
            IntPtr hWnd = handle;
            FLASHWINFO fInfo = new FLASHWINFO();

            fInfo.cbSize = Convert.ToUInt32(Marshal.SizeOf(fInfo));
            fInfo.hwnd = hWnd;
            fInfo.dwFlags = FLASHW_ALL | FLASHW_TIMERNOFG;
            fInfo.uCount = count;
            fInfo.dwTimeout = timeout;

            return FlashWindowEx(ref fInfo);
          }
        }
"@
    }
  }
  Process {
    ForEach ($handle in $MainWindowHandle) {
      Write-Verbose ("Flashing window: {0}" -f $handle)
      $null = [Window]::FlashWindow($handle,$FlashRate,$FlashCount)
    }
  }
}
function Show-CustomError {
<#
  .Synopsis
    Show detailed information about error
#>
  if ($Global:Error[0].InvocationInfo.Line)       {Write-Host "$($Global:TXT_RED)Error command:$($Global:TXT_CLEAR)`t$( ($Global:Error[0].InvocationInfo.Line).Trim() )"}
  if ($Global:Error[0].Exception.Message)         {Write-Host "$($Global:TXT_RED)Error message:$($Global:TXT_CLEAR)`t$($Global:Error[0].Exception.Message)"}
  [bool] $showScriptName = $false
  if ($Global:Error[0].InvocationInfo.ScriptName) {
    [string] $scriptName = $Global:Error[0].InvocationInfo.ScriptName
    $showScriptName = $true
  }
  if ($Global:Error[0].InvocationInfo.ScriptLineNumber) {
    $scriptName += ":$($Global:Error[0].InvocationInfo.ScriptLineNumber)"
  }
  if ($Global:Error[0].InvocationInfo.OffsetInLine){
    $scriptName += " char:$($Global:Error[0].InvocationInfo.OffsetInLine)"
  }
  if ($showScriptName)                            {Write-Host "$($Global:TXT_RED)Script name:$($Global:TXT_CLEAR)`t${scriptName}"}
  if ($Global:Error[0].ErrorDetails)              {Write-Host "$($Global:TXT_RED)Error details:$($Global:TXT_CLEAR)`t$($Global:Error[0].ErrorDetails)"}
}

function Get-IPsArray {
  <#
    .Synopsis
      IP calculator
    .Description
      Return hastable with IPs, Mask and other network info, by IP and mask
    .Parameter inputIpAddress
      IP address string
    .Parameter maskLength
      Mask length INT
    .Parameter inputIpAddressWithMask
      IP/mask length
    .EXAMPLE
      Get-IPsArray "192.168.100.15" 27
      Name                           Value
      ----                           -----
      availableIpCount               30
      availableIps                   192.168.100.1 - 192.168.100.30
      networkAddr                    192.168.100.0
      availableIpsArray              {192.168.100.1, 192.168.100.2, 192.168.100.3, 192.168.100.4...}
      broadcastAddr                  192.168.100.31
    .INPUTS
      [System.TimeSpan]
    .OUTPUTS
      [Hashtable]
    .NOTES
      NAME timeDurationOutput
      AUTHOR: Andrey Makovetsky (andrey@makovetsky.me)
      LASTEDIT: 2018-06-06
  #>
  [CmdletBinding(DefaultParameterSetName="ipAndMask")]
  param (
    [Parameter(Mandatory=$true,Position=0,HelpMessage="IP address",ParameterSetName="ipAndMask")]
      [ValidatePattern("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")]
      [string] $inputIpAddress,
    [Parameter(Mandatory=$false,Position=1,ParameterSetName="ipAndMask")]
      [ValidateRange(1,32)]
      [int] $maskLenght = 28,
    [Parameter(Mandatory=$true,Position=0,HelpMessage="IP address with mask",ParameterSetName="ipWithMask")]
      [ValidatePattern("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([1-9]|[1-2][\d]|3[0-2])$")]
      [string] $inputIpAddressWithMask
  )
  #TODO: count mask length by convert to binary numbering
  [hashtable] $addressesInMask = [ordered] @{
    24 = 256
    25 = 128
    26 = 64
    27 = 32
    28 = 16
    29 = 8
    30 = 4
    31 = 2
    32 = 0
  }
  if ($maskLenght -ge 24) {
    if ($inputIpAddress -match "^((\d{1,3}\.){3})(\d{1,3})$") {
      [string] $beginingAddressString = $Matches[1]
      [int] $lastOctet = $Matches[3]
    }
    [int] $networkMask = $lastOctet - $lastOctet % $addressesInMask.$maskLenght
  } elseif ($maskLenght -ge 16 -and $maskLenght -lt 24) {
  } elseif ($maskLenght -ge 8  -and $maskLenght -lt 16) {
  } else {}
  [string[]] $availableIps = $null;
  for ($i = $networkMask + 1; $i -le $networkMask + $addressesInMask.$maskLenght - 2;$i++) {
    $availableIps += "${beginingAddressString}${i}"
  }
  [hashtable] $outputIPdata = [ordered]@{
    availableIpCount = ($addressesInMask.$maskLenght - 2)
    availableIps = "${beginingAddressString}$($networkMask + 1) - ${beginingAddressString}$($networkMask + $addressesInMask.$maskLenght - 2)"
    availableIpsArray = $availableIps
    networkAddr = "${beginingAddressString}${networkMask}"
    broadcastAddr = "${beginingAddressString}$($networkMask + $addressesInMask.$maskLenght - 1)"
  }
  return $outputIPdata
}

function New-MultiThreadJob {
<#
.SYNOPSIS
  start job in multiply threads
.DESCRIPTION
  start multijob with items in array
.PARAMETER threadCommand
  scriptblock of command with param($argument)
.PARAMETER arguments
  array of arguments for multi-command
.PARAMETER maxThreads
  maximum threads number (default 5)
.EXAMPLE
  New-MultiThreadJob -threadCommand {param($argument);return $argument} -arguments "1","2","3","4","5" -maxThreads 3
  1
  2
  3
  4
  5
.NOTES
  NAME New-MultiThreadJob
  AUTHOR: Andrey Makovetsky (andrey@makovetsky.me)
  LASTEDIT: 2023-06-20
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true,Position=0)]
      [scriptblock] $threadCommand,
    [Parameter(Mandatory=$true,Position=1)]
      [array] $arguments,
    [Parameter(Mandatory=$false,Position=2)]
      [int] $maxThreads = 5
  )

  [array] $outputArray     = $null
  [int] $completedJobCount = 0

  Write-Verbose "preparing runspace"
  $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $maxThreads)
  $RunspacePool.Open()
  $sumulationJobs = @() 

  Write-Verbose "starting all jobs"
  foreach ($argument in $arguments) {
    $powershell = [powershell]::Create().AddScript($threadCommand).AddArgument($argument)
    $powershell.RunspacePool = $RunspacePool
    $sumulationJobs += New-Object PSObject -Property @{
      Job = $powershell
      Result = $powershell.BeginInvoke()
    }
  }

  Write-Verbose "waiting all jobs completed"
  while ($sumulationJobs.Result.IsCompleted -eq $false) {
    if ( ($sumulationJobs.Result.IsCompleted -eq $true).Count -gt $completedJobCount) {
      Write-Host "Completed " -NoNewline
      Write-Host $( ($sumulationJobs.Result.IsCompleted -eq $true).Count ) -ForegroundColor Green -NoNewline
      Write-Host "/$($sumulationJobs.Count)"
      $completedJobCount = ($sumulationJobs.Result.IsCompleted -eq $true).Count
    }
    Start-Sleep -Seconds 10
  }

  Write-Verbose "all done, collecting outputs"
  foreach ($job in $sumulationJobs) {
    $outputArray += $job.Job.EndInvoke($job.Result)
  }

  return $outputArray
}

Set-Alias -Name cflt ConvertFrom-LinuxTime
Set-Alias -Name ctlt ConvertTo-LinuxTime
Set-Alias -Name flash Invoke-FlashWindow
Set-Alias -Name glf  Get-LockedFileProcess
Set-Alias -Name grep Select-ColorString
Set-Alias -Name maaf Get-MAAFunctions
Set-Alias -Name nmtj New-MultiThreadJob
Set-Alias -Name ipcalc Get-IPsArray