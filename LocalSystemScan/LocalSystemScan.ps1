#Requires -RunAsAdministrator

#
# Declarations of the parameters for the script. This allows the PowerShell script to be executed in different combinations without directly modify the script file.
#
#
# The script can be executed in the following format:
# C:\> .\LocalSystemScan.ps1 [-getRService <System.Boolean>] [-getRProcess <System.Boolean>] [-getPSSessionConf <System.Boolean>] [-getDirInfo <System.Boolean>] [-getRegInfo <System.Boolean>] [-outFormat <System.String[]>] [-inputLoc <System.String[]>] [-outputLoc <System.String[]>]
#    
# Optional Parameters:
# -getRService:        Instruct the script whether the information of the running services should be collected or not. Default value: $false
# -getRProcess:        Instruct the script whether the information of the running processs should be collected or not. Default value: $false
# -getPSSessionConf:   Instruct the script whether the information of the powershell session configuration should be collected or not. Default value: $false
# -getDirInfo:         Instruct the script whether the information of the files and directories should be collected or not. Default value: $false
# -getRegInfo:         Instruct the script whether the information of the system registry should be collected or not. Default value: $false
# -outFormat:          Instruct the desired file format when the script save the data. Default value: JSontxt. Acceptable value:  JSon | JSonTXT | CSV | XML | HTML | FormatTXT | TXT
# -inputLoc:           Instruct the script to load the specified location when the files of directory list and registry list to be used by the script.
# -outputLoc:          Instruct the script to save the output files to the specified locations.
#
# Sample Usages:
# - To only collect the data of the running services
#   C:\> .\LocalSystemScan.ps1 -getRService $true
#
# - To only collect the data of the running processes
#   C:\> .\LocalSystemScan.ps1 -getRProcess $true
#
# - To only collect the data of the Powershell Session Configurations
#   C:\> .\LocalSystemScan.ps1 -getPSSessionConf $true
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
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][Boolean]  $getPSSessionConf,
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
$getPSSessionConfig      = $false;
$getDirectoryInfo        = $false;
$getRegistryInfo         = $false;

$currentLocation         = Get-Location;
$inputLocation           = $currentLocation;
$outputLocation          = $currentLocation;

$inputFileDirList        = "directory_list.txt";
$inputFileRegList        = "registry_list.txt";
$inputFileDirExList      = "directory_exclude.txt";
$outputFileRTError       = "RuntimeError.log";

$runtimeOutput           = ""+$currentLocation+"\"+$outputFileRTError;

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
if ($getRService -eq $true)       { $getRunningServices   = $getRService;  } 
if ($getRProcess -eq $true)       { $getRunningProcesses  = $getRProcess;  }
if ($getPSSessionConf -eq $true)  { $getPSSessionConfig   = $getPSSessionConf;  }
if ($getDirInfo  -eq $true)       { $getDirectoryInfo     = $getDirInfo;   }
if ($getRegInfo  -eq $true)       { $getRegistryInfo      = $getRegInfo;   }

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
$resetAllDefault = (($getRunningServices -eq $false) -and ($getRunningProcesses -eq $false) -and ($getPSSessionConfig -eq $false) -and ($getDirectoryInfo -eq $false) -and ($getRegistryInfo -eq $false));
If ($resetAllDefault -eq $true) {
    $getRunningServices     = $true;
    $getRunningProcesses    = $true;
    $getPSSessionConfig     = $true;
    $getDirectoryInfo       = $true;
    $getRegistryInfo        = $true;
}

#
#  Update the file locations of the input configuration files 
#
$dirRootListFile               = ""+$inputLocation+"\"+$inputFileDirList;
$dirExcludeListFile            = ""+$inputLocation+"\"+$inputFileDirExList;
$regRootListFile               = ""+$inputLocation+"\"+$inputFileRegList;

#
#  Update the file locations of the output error log files
#
$ErrorOutputFile        = ""+$outputLocation+"\Output_Error_"+$computeName+"_"+$timestamp+".log";

#
#  Verify the existence of the input configruation file for directory list.
#  If the configuration file does NOT exist, the walkthrough and data collections of files and directories will be disabled regardless the values of the input parameters.
#
if ((((Test-Path $dirRootListFile) -eq $false) -or ((Test-Path $dirExcludeListFile) -eq $false)) -and ($getDirectoryInfo -eq $true)) {
    $outString = $null;
    if ((Test-Path $dirRootListFile) -eq $false) { $outString += "["+(Get-Date).ToString('yyyy/MM/dd HH:mm:ss.sss')+"] - Unable to locate the directory list file ["+$dirRootListFile+"]. Directory walkthrough and data collection are disabled."  }
    if ((Test-Path $dirExcludeListFile) -eq $false) { $outString += "["+(Get-Date).ToString('yyyy/MM/dd HH:mm:ss.sss')+"] - Unable to locate the directory exlcude list file ["+$dirExcludeListFile+"]. Directory walkthrough and data collection are disabled."  }
    $outString | Out-File -append $runtimeOutput;
    $getDirectoryInfo = $false;
}

$inputFileDirEx = "";
if ((Test-Path $dirExcludeListFile) -eq $true) { $inputFileDirEx = ""+(Get-Content $inputFileDirExList)+""; }

#
#  Verify the existence of the input configruation file for registry list.
#  If the configuration file does NOT exist, the walkthrough and data collections of registry keys and values will be disabled regardless the values of the input parameters.
#
if (((Test-Path $regRootListFile) -eq $false) -and ($getRegistryInfo -eq $true)) {
    $outString = "["+(Get-Date).ToString('yyyy/MM/dd HH:mm:ss.sss')+"] - Unable to locate the registry list ["+$regRootListFile+"]. Registry walkthrough and data collection are disabled." 
    $outString | Out-File -append $runtimeOutput;
    $getRegistryInfo = $false; $getPerfMonInfo = $false;
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
$reportPSSessionConfig  = ""+$outputLocation+"\PSSession_Configurations_"+$computeName+"_"+$timestamp+$outputFileFormat+"";
$reportDirProperty      = ""+$outputLocation+"\Directory_Properties_"+$computeName+"_"+$timestamp+$outputFileFormat+"";
$reportDirPermission    = ""+$outputLocation+"\Directory_Permissions_"+$computeName+"_"+$timestamp+$outputFileFormat+"";
$reportRegProperty      = ""+$outputLocation+"\Registry_Properties_"+$computeName+"_"+$timestamp+$outputFileFormat+"";
$reportRegPermission    = ""+$outputLocation+"\Registry_Permissions_"+$computeName+"_"+$timestamp+$outputFileFormat+"";

#
# Function - Data Output
#
function outputAsJson {
    Param (
        [Parameter(Mandatory=$true,Position=0)] $data,
        [Parameter(Mandatory=$true,Position=1)] $target
    )
    $data | Select-Object -Property * | ConvertTo-Json | Out-File -Append $target;
}

function outputAsCsv {
    Param (
        [Parameter(Mandatory=$true,Position=0)] $data,
        [Parameter(Mandatory=$true,Position=1)] $target
    )
    $data | Select-Object -Property * | ConvertTo-Csv | Out-File -Append $target;
}

function outputAsXml {
    Param (
        [Parameter(Mandatory=$true,Position=0)] $data,
        [Parameter(Mandatory=$true,Position=1)] $target
    )
    $data | Select-Object -Property * | ConvertTo-Xml | Export-Clixml -Append $target;
}

function outputAsHtml {
    Param (
        [Parameter(Mandatory=$true,Position=0)] $data,
        [Parameter(Mandatory=$true,Position=1)] $target
    )
    $data | Select-Object -Property * | ConvertTo-Html | Out-File -Append $target;
}

function outputAsFormatTxt {
    Param (
        [Parameter(Mandatory=$true,Position=0)] $data,
        [Parameter(Mandatory=$true,Position=1)] $target
    )
    $data | Select-Object -Property * | ConvertTo-Json | ConvertFrom-Json | Out-File -Append $target;
}

function outputAsTxt {
    Param (
        [Parameter(Mandatory=$true,Position=0)] $data,
        [Parameter(Mandatory=$true,Position=1)] $target
    )
    $data | Select-Object -Property * | Format-Table -AutoSize -Wrap | Out-File -Append $target;
}

function exportData {
    Param (
        [Parameter(Mandatory=$true,Position=0)] $outputData,
        [Parameter(Mandatory=$true,Position=1)] $target
    )
    if (($outputFormat -eq "json") -or ($outputFormat -eq "jsontxt")) { outputAsJson $outputData $target; }
    if ($outputFormat -eq "csv")       {  outputAsCsv $outputData $target;  }
    if ($outputFormat -eq "xml")       {  outputAsXml $outputData $target;  }
    if ($outputFormat -eq "html")      {  outputAsHtml $outputData $target; }
    if ($outputFormat -eq "formattxt") {  outputAsFormatTxt $outputData $target; }
    if ($outputFormat -eq "txt")       {  outputAsTxt $outputData $target;    }
}

function gatherAttributes {
    Param (
        [Parameter(Mandatory=$true,Position=0)] $dataObject,
        [Parameter(Mandatory=$true,Position=1)] [String[]] $dataType
    )
    $ErrorOutput = $null;
    $iProp = Get-ItemProperty $dataObject.PsPath  -ErrorAction SilentlyContinue -ErrorVariable +ErrorOutput | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl;
    $iAcl = Get-Acl $dataObject.PsPath -ErrorAction SilentlyContinue -ErrorVariable +ErrorOutput | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl;
    if ($iProp -ne $null) {  
        if ($dataType -eq "directory") {  exportData $iProp $reportDirProperty;  }
        if ($dataType -eq "registry")  {  exportData $iProp $reportRegProperty;  }
    }
    if ($iAcl -ne $null)  {  
        if ($dataType -eq "directory") {  exportData $iAcl $reportDirPermission; }
        if ($dataType -eq "registry")  {  exportData $iAcl $reportRegPermission; }
    }
    if ($ErrorOutput.Count -gt 0)      {  outputAsJson $ErrorOutput $ErrorOutputFile; $ErrorOutput = $null;  }  
}

#
# Function - Collect the dynamic information of the local system, such as the running processes, services and applications.
#

function getSystemInformationDynamic {
    Param(
        [Parameter(Mandatory=$true)][String[]] $dataType
    )
    $data        = $null;
    $target      = $null;
    $ErrorOutput = $null;

    if ($dataType -eq "Process")       { $data = Get-Process * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput; $target = $reportRunningProcess;}
    if ($dataType -eq "Service")       { $data = Get-Service * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput; $target = $reportRunningService;}
    if ($dataType -eq "PSSessionConf") { $data = Get-PSSessionConfiguration * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput; $target = $reportPSSessionConfig;}

    if (($data -ne $null) -and ($target -ne $null))  {  exportData $data $target;  }
    if ($ErrorOutput.Count -gt 0)      {  outputAsJson $ErrorOutput $ErrorOutputFile;   }
}

#
# Function - Collect the static information of the local system, such as the properties and ACLs of the file system.
#

function getSystemInformationStatic {
    Param (
        [Parameter(Mandatory=$true,Position=0)][String[]] $dataType,
        [Parameter(Mandatory=$true,Position=1)][Boolean]  $isRecurse
    )

    $rootList = $null;
    $currentItem = $null;
    $ErrorOutput = $null;

    if ($dataType -eq "directory") {  $rootList = Get-Content $dirRootListFile;  }
    if ($dataType -eq "registry")  {  $rootList = Get-Content $regRootListFile;  }

    foreach ($list in $rootList){
        if ($dataType -eq "directory") {  if ($list -notmatch $inputFileDirEx) {$currentItem = $list; } }
        if ($dataType -eq "registry")  {  $currentItem = "Registry::"+$list; }

        if ($currentItem -ne $null) {
        if ((Test-Path $currentItem) -eq $true) {
            $rootItem = Get-Item -Path $currentItem -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput -Force;
            
            if ($ErrorOutput.Count -gt 0) { outputAsJson $ErrorOutput $ErrorOutputFile;  $ErrorOutput = $null;  }
            else { gatherAttributes $rootItem $dataType;  }  

            if ($isRecurse -eq $true) {
                if ($dataType -eq "directory") { $childItems = Get-ChildItem -Path $currentItem -Recurse -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput -Attributes !ReparsePoint | where {($_.LinkType -eq $null) -and ($_.DirectoryName -notlike "*\temp*")}; }
                if ($dataType -eq "registry")  { $childItems = Get-ChildItem -Path $currentItem -Recurse -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput -Force; }
                if ($ErrorOutput.Count -gt 0) { outputAsJson $ErrorOutput $ErrorOutputFile;  $ErrorOutput = $null;  }
                if ($childItems -ne $null) { foreach ($_ in $childItems) { 
                    if($dataType -eq "directory") { if($_.FullName -notmatch $inputFileDirEx) { gatherAttributes $_ $dataType; } }
                    if($dataType -eq "registry") { gatherAttributes $_ $dataType; } } }
                }
            }
        }
    }
}

#
#  Main parts to call out the relevant functions
#

if ($getRunningServices -eq $true)    { getSystemInformationDynamic "Service";        }
if ($getRunningProcesses -eq $true)   { getSystemInformationDynamic "Process";        }
if ($getPSSessionConfig -eq $true)    { getSystemInformationDynamic "PSSessionConf";  }
if ($getDirectoryInfo -eq $true)      { getSystemInformationStatic "Directory" $true; }
if ($getRegistryInfo -eq $true)       { getSystemInformationStatic "Registry" $true;  }