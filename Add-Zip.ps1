function Add-Zip ($Source, $Archive){
<#
    .SYNOPSIS
         Compression function

     .DESCRIPTION
         Native compression with latest .NET 4.5 framework

     .PARAMETER  Source
         Source file or directory for compression

     .PARAMETER  Archive
         Archive file name [with path]

     .EXAMPLE
         -------------------------- EXAMPLE 1 --------------------------
         Add-Zip -Source C:\Temp -Archive C:\Temp.zip

         Compress C:\temp folder to C:\temp.zip archive

         -------------------------- EXAMPLE 2 --------------------------
         Add-Zip -Source C:\Temp -Archive C:\Temp.zip

         Compress C:\temp folder to C:\temp.zip archive

     .LINK
         http://makovetsky.me
#>
If (-Not $Source -or -Not $Archive) {
Write-Host 'One or more parameters is missing'
} else {
Add-Type -Assembly "System.IO.Compression.FileSystem" ;
[System.IO.Compression.ZipFile]::CreateFromDirectory("$Source", "$Archive") ;
}}
