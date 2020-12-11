Param(
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][Boolean]  $getRService,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][Boolean]  $getRProcess,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][Boolean]  $getDirInfo,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][Boolean]  $getRegInfo,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][String[]] $outFormat,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][String[]] $inputLoc,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][String[]] $outputLoc
)

$getRunningServices      = $false;
$getRunningProcesses     = $false;
$getDirectoryInfo        = $false;
$getRegistryInfo         = $false;
$outputFormat            = "JSonTXT";

$currentLocation         = Get-Location;
$inputLocation           = $currentLocation;
$outputLocation          = $currentLocation;
$computeName             = $env:COMPUTERNAME;
$timestamp               = [int][double]::Parse((Get-Date -UFormat %s));
$runtimeOutput           = ""+$currentLocation+"\RuntimeError.log";

if (($getRService -eq $true))  { $getRunningServices   = $getRService;  } 
if (($getRProcess -eq $true))  { $getRunningProcesses  = $getRProcess;  }
if (($getDirInfo  -eq $true))  { $getDirectoryInfo     = $getDirInfo;   }
if (($getRegInfo  -eq $true))  { $getRegistryInfo      = $getRegInfo;   }

If ($outFormat -ne $null)      {
    if (($outFormat -eq "JsonTXT") -or ($outFormat -eq "Json") -or ($outFormat -eq "XML") -or ($outFormat -eq "TXT") -or ($outFormat -eq "HTML") -or ($outFormat -eq "CSV") -or ($outFormat -eq "FormatTXT")) {$outputFormat = $outFormat;}
    else { "Invalid output format. The output format can only be CSV, Json, JsonTXT, XML, HTML, FormatTXT, TXT. Use the default output formation JsonTXT instead." | Out-File -Append $runtimeOutput    }
}

IF ($inputLoc -ne $null)       {
    if (((Test-Path $inputLoc) -eq $true)) {$inputLocation = $inputLoc;}
    else { "Invalid input location ["+$inputLoc+"]. Use the default input location ["+$inputLocation+"] instead." | Out-File -Append $runtimeOutput;    }
}

IF ($outputLoc -ne $null)      {
    if (((Test-Path $outputLoc) -eq $true)) {$outputLocation = $outputLoc;}
    else { "Invalid output location ["+$outputLoc+"]. Use the default out location ["+$outputLocation+"] instead." | Out-File -Append $runtimeOutput;    }
}

If (($getRunningServices -eq $false) -and ($getRunningProcesses -eq $false) -and ($getDirectoryInfo -eq $false) -and ($getRegistryInfo -eq $false)) {
    $getRunningServices     = $true;
    $getRunningProcesses    = $true;
    $getDirectoryInfo       = $true;
    $getRegistryInfo        = $true;
}

$dirRootListFile            = ""+$inputLocation+"\directory_list.txt";
$regRootListFile            = ""+$inputLocation+"\registry_list.txt";

$ErrorOutput                   = $null;
$ErrorOutputFile               = ""+$outputLocation+"\Output_Error_"+$computeName+"_"+$timestamp+".log";

if ((Test-Path $dirRootListFile) -eq $false) {
    "Unable to locate the directory list file ["+$dirRootListFile+"]. Directory walkthrough and data collection are disabled." | Out-File -append $runtimeOutput;
    $getDirectoryInfo = $false;
}

if ((Test-Path $regRootListFile) -eq $false) {
    "Unable to locate the registry list ["+$regRootListFile+"]. Registry walkthrough and data collection are disabled." | Out-File -append $runtimeOutput;
    $getRegistryInfo = $false;
}

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


function getRuningServices {
    if (($outputFormat -eq "json") -or ($outputFormat -eq "jsontxt")) {  Get-Service * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | ConvertTo-Json | Out-File $reportRunningService    }
    if ($outputFormat -eq "csv")       {  Get-Service * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | ConvertTo-Csv | Out-File $reportRunningService     }
    if ($outputFormat -eq "xml")       {  Get-Service * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | ConvertTo-Xml | Export-Clixml $reportRunningService    }
    if ($outputFormat -eq "html")      {  Get-Service * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | ConvertTo-Html | Out-File $reportRunningService    }
    if ($outputFormat -eq "formattxt") {  Get-Service * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | ConvertTo-Json | ConvertFrom-Json | Out-File $reportRunningService    }
    if ($outputFormat -eq "txt")       {  Get-Service * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | Format-Table -AutoSize -Wrap | Out-File $reportRunningService    }
    if ($ErrorOutput.Count -gt 0)      {  $ErrorOutput | Select-Object -Property * | ConvertTo-Json | Out-File $ErrorOutputFile;   }
}

function getRunningProcesses {
    if (($outputFormat -eq "json") -or ($outputFormat -eq "jsontxt")) {  Get-Process * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | ConvertTo-Json | Out-File $reportRunningProcess    }
    if ($outputFormat -eq "csv")       {  Get-Process * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | ConvertTo-Csv | Out-File $reportRunningProcess    }
    if ($outputFormat -eq "xml")       {  Get-Process * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | ConvertTo-Xml | Export-Clixml $reportRunningProcess    }
    if ($outputFormat -eq "html")      {  Get-Process * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | ConvertTo-Html | Out-File $reportRunningProcess   }
    if ($outputFormat -eq "formattxt") {  Get-Process * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | ConvertTo-Json | ConvertFrom-Json | Out-File $reportRunningProcess    }
    if ($outputFormat -eq "txt")       {  Get-Process * -ErrorAction SilentlyContinue -ErrorVariable ErrorOutput | Select-Object -Property * | Format-Table -AutoSize -Wrap | Out-File $reportRunningProcess    }
    if ($ErrorOutput.Count -gt 0)      {  $ErrorOutput | Select-Object -Property * | ConvertTo-Json | Out-File $ErrorOutputFile;  }
}

function getDirectoryInformation {
   $dirRootList = Get-Content $dirRootListFile;
   foreach ($dirList in $dirRootList){
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

function getRegistryInformation {
   $regRootList = Get-Content $regRootListFile
   foreach ($regList in $regRootList){
       $actionItem = Get-ChildItem -Path Registry::$regList -Recurse -ErrorAction Continue -ErrorVariable ErrorOutput;
       foreach ($_ in $actionItem){
            $iProp = Get-ItemProperty $_.PsPath -ErrorAction Continue -ErrorVariable +ErrorOutput | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,Access,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl;
            $iAcl = Get-Acl $_.PsPath -ErrorAction Continue -ErrorVariable +ErrorOutput | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,Access,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl;
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

if ($getRunningServices -eq $true)    { getRuningServices;       }
if ($getRunningProcesses -eq $true)   { getRunningProcesses;     }
if ($getDirectoryInfo -eq $true)      { getDirectoryInformation; }
if ($getRegistryInfo -eq $true)       { getRegistryInformation;  }