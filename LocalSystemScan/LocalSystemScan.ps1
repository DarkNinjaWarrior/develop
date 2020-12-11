#
# Declarations of the parameters for the script. This allows the PowerShell script to be executed in different combinations without directly modify the script file.
#
# The script can be executed in the following format:
# C:\> .\LocalSystemScan.ps1 [-getRService <System.Boolean>] [-getRProcess <System.Boolean>] [-getDirInfo <System.Boolean>] [-getRegInfo <System.Boolean>] [-outFormat <System.String[]>] [-inputLoc <System.String[]>] [-outputLoc <System.String[]>]
#    
# Optional Parameters:
# -getRService:  Instruct the script whether the information of the running services should be collected or not. Default value: $false
# -getRProcess:  Instruct the script whether the information of the running processs should be collected or not. Default value: $false
# -getDirInfo:   Instruct the script whether the information of the files and directories should be collected or not. Default value: $false
# -getRegInfo:   Instruct the script whether the information of the system registry should be collected or not. Default value: $false
# -outFormat:    Instruct the desired file format when the script save the data. Default value: JSontxt. Acceptable value:  JSon | JSonTXT | CSV | XML | HTML | FormatTXT | TXT
# -inputLoc:     Instruct the script to load the specified location when the files of directory list and registry list to be used by the script.
# -outputLoc:    Instruct the script to save the output files to the specified locations.
#
# Sample Usages:
# - To only collect the data of the running services
#   C:\> .\LocalSystemScan.ps1 -getRService $true
#
# - To only collect the data of the running processes
#   C:\> .\LocalSystemScan.ps1 -getRProcess $true
#
# - To only collect the data on directories and files
#   C:\> .\LocalSystemScan.ps1 -getDirInfo $true
#
# - To only collect the data on system registry keys
#   C:\> .\LocalSystemScan.ps1 -getRegInfo $true
#
# - To only collect the data of the running services and save the output files to different locations
#   C:\> .\LocalSystemScan.ps1 -getRService $true -outputLoc <output_file_path>
#
# - To only collect the data on directories and files and load the monitoring list from different locations
#   C:\> .\LocalSystemScan.ps1 -getDirInfo $true -inputLoc <input_file_path>
#
# - To only collect the data on system registry keys with a monitoring list from a different location and then save the output files to a different location
#   C:\> .\LocalSystemScan.ps1 -getRegInfo $true -inputLoc <input_file_path> -outputLoc <output_file_path>
#

Param(
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][Boolean]  $getRService,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][Boolean]  $getRProcess,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][Boolean]  $getDirInfo,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][Boolean]  $getRegInfo,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][String[]] $outFormat,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][String[]] $inputLoc,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][String[]] $outputLoc
)

#
#  Global Variable Section. DO NOT MODIFY.
#
$getRunningServices      = $false;
$getRunningProcesses     = $false;
$getDirectoryInfo        = $false;
$getRegistryInfo         = $false;

$currentLocation         = Get-Location;
$inputLocation           = $currentLocation;
$outputLocation          = $currentLocation;

$runtimeOutput           = ""+$currentLocation+"\RuntimeError.log";

$ErrorOutput             = $null;

#
#  Default output format.
#  Acceptable value:  JSon | JSonTXT | CSV | XML | HTML | FormatTXT | TXT
#  - JSon:            Output in JSon structure with the file extension .json
#  - JSonTXT:         Output in JSon structure with the file extension .txt
#  - CSV:             Output in CSV format with the file extension .csv
#  - XML:             Output in XML format with the file extension .xml
#  - HTML:            Output in HTML format with the file extension .html
#  - FormatTXT:       Output in TEXT format converted from JSon output with the file extension .txt
#  - TXT:             Output in TEXT RAW format with the file extension .txt
#
$outputFormat            = "JSonTXT";

#
#  Functional Variables to create the unique output files each time when the script is executed. 
#
$computeName             = $env:COMPUTERNAME;
$timestamp               = [int][double]::Parse((Get-Date -UFormat %s));

#
# Validate the input parameters and pass the values to the variables
#

#
# Determine the required data to be collected from the input parameters.
#
if (($getRService -eq $true))  { $getRunningServices   = $getRService;  } 
if (($getRProcess -eq $true))  { $getRunningProcesses  = $getRProcess;  }
if (($getDirInfo  -eq $true))  { $getDirectoryInfo     = $getDirInfo;   }
if (($getRegInfo  -eq $true))  { $getRegistryInfo      = $getRegInfo;   }

#
# Determine the output file format from the input parameters.
#
If ($outFormat -ne $null)      {
    if (($outFormat -eq "JsonTXT") -or ($outFormat -eq "Json") -or ($outFormat -eq "XML") -or ($outFormat -eq "TXT") -or ($outFormat -eq "HTML") -or ($outFormat -eq "CSV") -or ($outFormat -eq "FormatTXT")) {$outputFormat = $outFormat;}
    else { 
        $outString = "["+(Get-Date).ToString('yyyy/MM/dd HH:mm:ss')+"] - Invalid output format. The output format can only be CSV, Json, JsonTXT, XML, HTML, FormatTXT, TXT. Use the default output formation JsonTXT instead." 
        $outString | Out-File -Append $runtimeOutput;    }
}

#
# Determine the file location of the input configuration files from the input parameters.
#
IF ($inputLoc -ne $null)       {
    if (((Test-Path $inputLoc) -eq $true)) {$inputLocation = $inputLoc;}
    else { 
        $outString = "["+(Get-Date).ToString('yyyy/MM/dd HH:mm:ss')+"] - Invalid input location ["+$inputLoc+"]. Use the default input location ["+$inputLocation+"] instead." 
        $outString | Out-File -Append $runtimeOutput;    }
}

#
# Determine the output file location from the input parameters.
#
IF ($outputLoc -ne $null)      {
    if (((Test-Path $outputLoc) -eq $true)) {$outputLocation = $outputLoc;}
    else { 
        $outString = "["+(Get-Date).ToString('yyyy/MM/dd HH:mm:ss')+"] - Invalid output location ["+$outputLoc+"]. Use the default out location ["+$outputLocation+"] instead." 
        $outString | Out-File -Append $runtimeOutput;    }
}

#
# Error control: Enable ALL the options as default when none of them was enalbed through the input vairable.
#
If (($getRunningServices -eq $false) -and ($getRunningProcesses -eq $false) -and ($getDirectoryInfo -eq $false) -and ($getRegistryInfo -eq $false)) {
    $getRunningServices     = $true;
    $getRunningProcesses    = $true;
    $getDirectoryInfo       = $true;
    $getRegistryInfo        = $true;
}

#
#  Update the file locations of the input configuration files 
#
$dirRootListFile               = ""+$inputLocation+"\directory_list.txt";
$regRootListFile               = ""+$inputLocation+"\registry_list.txt";

#
#  Update the file locations of the output error log files
#
$ErrorOutputFile               = ""+$outputLocation+"\Output_Error_"+$computeName+"_"+$timestamp+".log";

#
#  Verify the existence of the input configruation file for directory list.
#  If the configuration file does NOT exist, the walkthrough and data collections of files and directories will be disabled regardless the values of the input parameters.
#
if (((Test-Path $dirRootListFile) -eq $false) -and ($getDirectoryInfo -eq $true)) {
    $outString = "["+(Get-Date).ToString('yyyy/MM/dd HH:mm:ss.sss')+"] - Unable to locate the directory list file ["+$dirRootListFile+"]. Directory walkthrough and data collection are disabled." 
    $outString | Out-File -append $runtimeOutput;
    $getDirectoryInfo = $false;
}

#
#  Verify the existence of the input configruation file for registry list.
#  If the configuration file does NOT exist, the walkthrough and data collections of registry keys and values will be disabled regardless the values of the input parameters.
#
if (((Test-Path $regRootListFile) -eq $false) -and ($getRegistryInfo -eq $true)) {
    $outString = "["+(Get-Date).ToString('yyyy/MM/dd HH:mm:ss.sss')+"] - Unable to locate the registry list ["+$regRootListFile+"]. Registry walkthrough and data collection are disabled." 
    $outString | Out-File -append $runtimeOutput;
    $getRegistryInfo = $false;
}

#
# Section of the output file formats.
#
$outputFileFormat = ".txt";

if ($outputFormat -eq "xml")  { $outputFileFormat = ".xml";  }
if ($outputFormat -eq "html") { $outputFileFormat = ".html"; }
if ($outputFormat -eq "csv")  { $outputFileFormat = ".csv";  }
if ($outputFormat -eq "json") { $outputFileFormat = ".json"; }

$reportRunningService   = ""+$outputLocation+"\Running_Services_"+$computeName+"_"+$timestamp+$outputFileFormat+"";
$reportRunningProcess   = ""+$outputLocation+"\Running_Processes_"+$computeName+"_"+$timestamp+$outputFileFormat+"";
$reportDirProperty      = ""+$outputLocation+"\Directory_Properties_"+$computeName+"_"+$timestamp+$outputFileFormat+"";
$reportDirPermission    = ""+$outputLocation+"\Directory_Permissions_"+$computeName+"_"+$timestamp+$outputFileFormat+"";
$reportRegProperty      = ""+$outputLocation+"\Registry_Properties_"+$computeName+"_"+$timestamp+$outputFileFormat+"";
$reportRegPermission    = ""+$outputLocation+"\Registry_Permissions_"+$computeName+"_"+$timestamp+$outputFileFormat+"";

#
# Function - Collect the information of the running services for the local system.
#
function getRuningServices {
    if (($outputFormat -eq "json") -or ($outputFormat -eq "jsontxt")) {  Get-Service * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | ConvertTo-Json | Out-File $reportRunningService    }
    if ($outputFormat -eq "csv")       {  Get-Service * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | ConvertTo-Csv | Out-File $reportRunningService     }
    if ($outputFormat -eq "xml")       {  Get-Service * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | ConvertTo-Xml | Export-Clixml $reportRunningService    }
    if ($outputFormat -eq "html")      {  Get-Service * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | ConvertTo-Html | Out-File $reportRunningService    }
    if ($outputFormat -eq "formattxt") {  Get-Service * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | ConvertTo-Json | ConvertFrom-Json | Out-File $reportRunningService    }
    if ($outputFormat -eq "txt")       {  Get-Service * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | Format-Table -AutoSize -Wrap | Out-File $reportRunningService    }
    if ($ErrorOutput.Count -gt 0)      {  $ErrorOutput | Select-Object -Property * | ConvertTo-Json | Out-File $ErrorOutputFile;   }
}

#
# Function - Collect the information of the running processes for the local system.
#
function getRunningProcesses {
    if (($outputFormat -eq "json") -or ($outputFormat -eq "jsontxt")) {  Get-Process * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | ConvertTo-Json | Out-File $reportRunningProcess    }
    if ($outputFormat -eq "csv")       {  Get-Process * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | ConvertTo-Csv | Out-File $reportRunningProcess    }
    if ($outputFormat -eq "xml")       {  Get-Process * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | ConvertTo-Xml | Export-Clixml $reportRunningProcess    }
    if ($outputFormat -eq "html")      {  Get-Process * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | ConvertTo-Html | Out-File $reportRunningProcess   }
    if ($outputFormat -eq "formattxt") {  Get-Process * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | ConvertTo-Json | ConvertFrom-Json | Out-File $reportRunningProcess    }
    if ($outputFormat -eq "txt")       {  Get-Process * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | Format-Table -AutoSize -Wrap | Out-File $reportRunningProcess    }
    if ($ErrorOutput.Count -gt 0)      {  $ErrorOutput | Select-Object -Property * | ConvertTo-Json | Out-File $ErrorOutputFile;  }
}

#
# Function - Collect the information of the desired files and directories to be monitored on the local system.
#
function getDirectoryInformation {
   $dirRootList = Get-Content $dirRootListFile;
   foreach ($dirList in $dirRootList){
       $rootItem = Get-Item -Path $dirList -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput;
       if ($ErrorOutput.Count -gt 0) { $ErrorOutput | Select-Object -Property * | ConvertTo-Json | Out-File -append $ErrorOutputFile;  $ErrorOutput = $null;  }
       else {
            $cProp = Get-ItemProperty $rootItem.PsPath  -ErrorAction SilentlyContinue -ErrorVariable +ErrorOutput | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl;
            $cAcl = Get-Acl $rootItem.PsPath -ErrorAction SilentlyContinue -ErrorVariable +ErrorOutput | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl
            if (($outputFormat -eq "json") -or ($outputFormat -eq "jsontxt")){ $cProp | ConvertTo-Json | Out-File -append $reportDirProperty; $cAcl | ConvertTo-Json | Out-File -append $reportDirPermission }
            if ($outputFormat -eq "csv")       {  $cProp | ConvertTo-Csv | Out-File -append $reportDirProperty; $cAcl | ConvertTo-Csv | Out-File -append $reportDirPermission }
            if ($outputFormat -eq "xml")       {  $cProp | ConvertTo-Xml | Export-Clixml -append $reportDirProperty; $cAcl | ConvertTo-Xml | Export-Clixml -append $reportDirPermission }
            if ($outputFormat -eq "html")      {  $cProp | ConvertTo-Html | Out-File -append $reportDirProperty; $cAcl | ConvertTo-Html | Out-File -append $reportDirPermission }
            if ($outputFormat -eq "formattxt") {  $cProp | ConvertTo-Json | ConvertFrom-Json | Out-File -append $reportDirProperty; $cAcl | ConvertTo-Json | ConvertFrom-Json | Out-File -append $reportDirPermission }
            if ($outputFormat -eq "txt")       {  $cProp | Format-Table -AutoSize -Wrap | Out-File -append $reportDirProperty; $cAcl | Format-Table -AutoSize -Wrap | Out-File -append $reportDirPermission }
            if ($ErrorOutput.Count -gt 0)      {  $ErrorOutput | Select-Object -Property * | ConvertTo-Json | Out-File -append $ErrorOutputFile; $ErrorOutput = $null;  }      
       }

       $actionItem = Get-ChildItem -Path $dirList -Recurse -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput;
       if ($ErrorOutput.Count -gt 0)      {  $ErrorOutput | Select-Object -Property * | ConvertTo-Json | Out-File -append $ErrorOutputFile;  $ErrorOutput = $null;  }
       foreach ($_ in $actionItem){
            $iProp = Get-ItemProperty $_.PsPath  -ErrorAction SilentlyContinue -ErrorVariable +ErrorOutput | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl;
            $iAcl = Get-Acl $_.PsPath -ErrorAction SilentlyContinue -ErrorVariable +ErrorOutput | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl
            if (($outputFormat -eq "json") -or ($outputFormat -eq "jsontxt")){ $iProp | ConvertTo-Json | Out-File -append $reportDirProperty; $iAcl | ConvertTo-Json | Out-File -append $reportDirPermission }
            if ($outputFormat -eq "csv")       {  $iProp | ConvertTo-Csv | Out-File -append $reportDirProperty; $iAcl | ConvertTo-Csv | Out-File -append $reportDirPermission }
            if ($outputFormat -eq "xml")       {  $iProp | ConvertTo-Xml | Export-Clixml -append $reportDirProperty; $iAcl | ConvertTo-Xml | Export-Clixml -append $reportDirPermission }
            if ($outputFormat -eq "html")      {  $iProp | ConvertTo-Html | Out-File -append $reportDirProperty; $iAcl | ConvertTo-Html | Out-File -append $reportDirPermission }
            if ($outputFormat -eq "formattxt") {  $iProp | ConvertTo-Json | ConvertFrom-Json | Out-File -append $reportDirProperty; $iAcl | ConvertTo-Json | ConvertFrom-Json | Out-File -append $reportDirPermission }
            if ($outputFormat -eq "txt")       {  $iProp | Format-Table -AutoSize -Wrap | Out-File -append $reportDirProperty; $iAcl | Format-Table -AutoSize -Wrap | Out-File -append $reportDirPermission }
            if ($ErrorOutput.Count -gt 0)      {  $ErrorOutput | Select-Object -Property * | ConvertTo-Json | Out-File -append $ErrorOutputFile; $ErrorOutput = $null;  }
       }
   }
}

#
# Function - Collect the information of the desired registry keys and values to be monitored on the local system.
#
function getRegistryInformation {
   $regRootList = Get-Content $regRootListFile;
   foreach ($regList in $regRootList){
   $rootItem = Get-Item -Path Registry::$regList -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput;
   if ($ErrorOutput.Count -gt 0) { $ErrorOutput | Select-Object -Property * | ConvertTo-Json | Out-File -append $ErrorOutputFile;  $ErrorOutput = $null;  }

   $actionItem = Get-ChildItem -Path Registry::$regList -Recurse -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput;
   if ($ErrorOutput.Count -gt 0) { $ErrorOutput | Select-Object -Property * | ConvertTo-Json | Out-File -append $ErrorOutputFile;  $ErrorOutput = $null;  }
   foreach ($_ in $actionItem){
            $iProp = Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue -ErrorVariable +ErrorOutput | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,Access,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl;
            $iAcl = Get-Acl $_.PsPath -ErrorAction SilentlyContinue -ErrorVariable +ErrorOutput | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,Access,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl;
            if (($outputFormat -eq "json") -or ($outputFormat -eq "jsontxt")){ $iProp | ConvertTo-Json | Out-File -append $reportRegProperty; $iAcl | ConvertTo-Json | Out-File -append $reportRegPermission }
            if ($outputFormat -eq "csv")       {  $iProp | ConvertTo-Csv | Out-File -append $reportRegProperty; $iAcl | ConvertTo-Csv | Out-File -append $reportRegPermission }
            if ($outputFormat -eq "xml")       {  $iProp | ConvertTo-Xml | Export-Clixml -append $reportRegProperty; $iAcl | ConvertTo-Xml | Export-Clixml -append $reportRegPermission }
            if ($outputFormat -eq "html")      {  $iProp | ConvertTo-Html | Out-File -append $reportRegProperty; $iAcl | ConvertTo-Html | Out-File -append $reportRegPermission }
            if ($outputFormat -eq "formattxt") {  $iProp | ConvertTo-Json | ConvertFrom-Json | Out-File -append $reportRegProperty; $iAcl | ConvertTo-Json | ConvertFrom-Json | Out-File -append $reportRegPermission }
            if ($outputFormat -eq "txt")       {  $iProp | Format-Table -AutoSize -Wrap | Out-File -append $reportRegProperty; $iAcl | Format-Table -AutoSize -Wrap | Out-File -append $reportRegPermission }
            if ($ErrorOutput.Count -gt 0)      {  $ErrorOutput | Select-Object -Property * | ConvertTo-Json | Out-File -append $ErrorOutputFile;  $ErrorOutput = $null;  }
       }

   }
}

#
#  Main parts to call out the relevant functions
#
if ($getRunningServices -eq $true)    { getRuningServices;       }
if ($getRunningProcesses -eq $true)   { getRunningProcesses;     }
if ($getDirectoryInfo -eq $true)      { getDirectoryInformation; }
if ($getRegistryInfo -eq $true)       { getRegistryInformation;  }