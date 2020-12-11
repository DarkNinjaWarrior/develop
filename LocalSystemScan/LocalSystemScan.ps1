Param(
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][Boolean] $getRService,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][Boolean] $getRProcess,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][Boolean] $getDirInfo,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][Boolean] $getRegInfo,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][String[]] $outFormat,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][String[]] $inputLoc,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false)][String[]] $outputLoc
)

$getRunningServices = $false;
$getRunningProcesses = $false;
$getDirectoryInfo = $false;
$getRegistryInfo = $false;
$outputFormat = "JSonTXT";

$currentLocation = Get-Location;
$inputLocation = $currentLocation;
$outputLocation = $currentLocation;
$computeName = $env:COMPUTERNAME;
$timestamp = [int][double]::Parse((Get-Date -UFormat %s));

If ($getRService -ne $null) {
    if (($getRService -eq $true) -or ($getRService -eq $false)) {$getRunningServices = $getRService;}
}

If ($getRProcess -ne $null) {
    if (($getRProcess -eq $true) -or ($getRProcess -eq $false)) {$getRunningProcesses = $getRProcess;}
}

If ($getDirInfo -ne $null) {
    if (($getDirInfo -eq $true) -or ($getDirInfo -eq $false)) {$getDirectoryInfo = $getDirInfo;}
}

If ($getRegInfo -ne $null) {
    if (($getRegInfo -eq $true) -or ($getRegInfo -eq $false)) {$getRegistryInfo = $getRegInfo;}
}

If ($outFormat -ne $null) {
    if (($outFormat -eq "JsonTXT") -or ($outFormat -eq "Json") -or ($outFormat -eq "XML") -or ($outFormat -eq "TXT") -or ($outFormat -eq "HTML") -or ($outFormat -eq "CSV")) {$outputFormat = $outFormat;}
}

IF ($inputLoc -ne $null){
    $dirInputFile = ""+$inputLoc+"\directory_list.txt";
    $regInputFile = ""+$inputLoc+"\registry_list.txt";
    if (((Test-Path $dirInputFile) -eq $true) -and ((Test-Path $regInputFile) -eq $true)) {
        $inputLocation = $inputLoc;
    }
}

IF ($outputLoc -ne $null){
    if (((Test-Path $outputLoc) -eq $true)) {
        $outputLocation = $outputLoc;
    }
}

If (($getRunningServices -eq $false) -and ($getRunningProcesses -eq $false) -and ($getDirectoryInfo -eq $false) -and ($getRegistryInfo -eq $false)){
    $getRunningServices = $true;
    $getRunningProcesses = $true;
    $getDirectoryInfo = $true;
    $getRegistryInfo = $true;
}

$dirRootListFile = ""+$inputLocation+"\directory_list.txt";
$regRootListFile = ""+$inputLocation+"\registry_list.txt";

$outputFileFormat = ".txt";
if ($outputFormat -eq "xml") {$outputFileFormat = ".xml";}
if ($outputFormat -eq "html") {$outputFileFormat = ".html";}
if ($outputFormat -eq "csv") {$outputFileFormat = ".csv";}
if ($outputFormat -eq "json") {$outputFileFormat = ".json";}

$reportRunningService = ""+$outputLocation+"\Running_Services_"+$computeName+"_"+$timestamp+$outputFileFormat+"";
$reportRunningProcess = ""+$outputLocation+"\Running_Processes_"+$computeName+"_"+$timestamp+$outputFileFormat+"";
$reportDirProperty = ""+$outputLocation+"\Directory_Properties_"+$computeName+"_"+$timestamp+$outputFileFormat+"";
$reportDirPermission = ""+$outputLocation+"\Directory_Permissions_"+$computeName+"_"+$timestamp+$outputFileFormat+"";
$reportRegProperty = ""+$outputLocation+"\Registry_Properties_"+$computeName+"_"+$timestamp+$outputFileFormat+"";
$reportRegPermission = ""+$outputLocation+"\Registry_Permissions_"+$computeName+"_"+$timestamp+$outputFileFormat+"";

function getRuningServices {
    if (($outputFormat -eq "json") -or ($outputFormat -eq "jsontxt")) {Get-Service * | ConvertTo-Json | Out-File $reportRunningService}
    if ($outputFormat -eq "csv") {Get-Service * | Select-Object -Property * | ConvertTo-Csv | Out-File $reportRunningService}
    if ($outputFormat -eq "xml") {Get-Service * | Select-Object -Property * | ConvertTo-Xml | Export-Clixml $reportRunningService}
    if ($outputFormat -eq "html") {Get-Service * | Select-Object -Property * | ConvertTo-Html | Out-File $reportRunningService}
    if ($outputFormat -eq "txt") {Get-Service * | Select-Object -Property * | Format-Table -AutoSize -Wrap | Out-File $reportRunningService}
}

function getRunningProcesses {
    if (($outputFormat -eq "json") -or ($outputFormat -eq "jsontxt")) {Get-Process * | ConvertTo-Json | Out-File $reportRunningProcess}
    if ($outputFormat -eq "csv") {Get-Process * | Select-Object -Property * | ConvertTo-Csv | Out-File $reportRunningProcess}
    if ($outputFormat -eq "xml") {Get-Process * | Select-Object -Property * | ConvertTo-Xml | Export-Clixml $reportRunningProcess}
    if ($outputFormat -eq "html") {Get-Process * | Select-Object -Property * | ConvertTo-Html | Out-File $reportRunningProcess}
    if ($outputFormat -eq "txt") {Get-Process * | Select-Object -Property * | Format-Table -AutoSize -Wrap | Out-File $reportRunningProcess}
}

function getDirectoryInformation {
   $dirRootList = Get-Content $dirRootListFile;
   foreach ($dirList in $dirRootList){
       $actionItem = Get-ChildItem -Path $dirList -Recurse;
       if (($outputFormat -eq "json") -or ($outputFormat -eq "jsontxt")) {$actionItem | ForEach-Object -Begin $null -Process {Get-ItemProperty $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl | ConvertTo-Json | Out-File -append $reportDirProperty },{Get-Acl $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl | ConvertTo-Json | Out-File -append $reportDirPermission } -End $null}
       if ($outputFormat -eq "csv") {$actionItem | ForEach-Object -Begin $null -Process {Get-ItemProperty $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl | ConvertTo-Csv | Out-File -append $reportDirProperty },{Get-Acl $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl | ConvertTo-Csv | Out-File -append $reportDirPermission } -End $null}
       if ($outputFormat -eq "xml") {$actionItem | ForEach-Object -Begin $null -Process {Get-ItemProperty $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl | ConvertTo-Xml | Export-Clixml -append $reportDirProperty },{Get-Acl $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl | ConvertTo-Xml | Export-Clixml -append $reportDirPermission } -End $null}
       if ($outputFormat -eq "html") {$actionItem | ForEach-Object -Begin $null -Process {Get-ItemProperty $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl | ConvertTo-Html | Out-File -append $reportDirProperty },{Get-Acl $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl | ConvertTo-Html | Out-File -append $reportDirPermission } -End $null}
       if ($outputFormat -eq "txt") {$actionItem | ForEach-Object -Begin $null -Process {Get-ItemProperty $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl | Format-Table -AutoSize -Wrap | Out-File -append $reportDirProperty },{Get-Acl $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl | Format-Table -AutoSize -Wrap | Out-File -append $reportDirPermission } -End $null}
   }
}

function getRegistryInformation {
   $regRootList = Get-Content $regRootListFile
   foreach ($regList in $regRootList){
       $actionItem = Get-ChildItem -Path Registry::$regList -Recurse
       if (($outputFormat -eq "json") -or ($outputFormat -eq "jsontxt")) {$actionItem | ForEach-Object -Begin $null -Process {Get-ItemProperty $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider | ConvertTo-Json | Out-File -append $reportRegProperty },{Get-Acl $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,Access,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl | ConvertTo-Json | Out-File -append $reportRegPermission } -End $null}
       if ($outputFormat -eq "csv") {$actionItem | ForEach-Object -Begin $null -Process {Get-ItemProperty $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider | ConvertTo-Csv | Out-File -append $reportRegProperty },{Get-Acl $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,Access,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl | ConvertTo-Csv | Out-File -append $reportRegPermission } -End $null}
       if ($outputFormat -eq "xml") {$actionItem | ForEach-Object -Begin $null -Process {Get-ItemProperty $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider | ConvertTo-Xml | Export-Clixml -append $reportRegProperty },{Get-Acl $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,Access,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl | ConvertTo-Xml | Export-Clixml -append $reportRegPermission } -End $null}
       if ($outputFormat -eq "html") {$actionItem | ForEach-Object -Begin $null -Process {Get-ItemProperty $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider | ConvertTo-Html | Out-File -append $reportRegProperty },{Get-Acl $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,Access,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl | ConvertTo-Html | Out-File -append $reportRegPermission } -End $null}
       if ($outputFormat -eq "txt") {$actionItem | ForEach-Object -Begin $null -Process {Get-ItemProperty $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider | Format-Table -AutoSize -Wrap | Out-File -append $reportRegProperty },{Get-Acl $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,Access,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl | Format-Table -AutoSize -Wrap | Out-File -append $reportRegPermission } -End $null}
   }
}

if ($getRunningServices -eq $true){
    getRuningServices;
}

if ($getRunningProcesses -eq $true){
    getRunningProcesses;
}

if($getDirectoryInfo -eq $true){
    getDirectoryInformation;
}

if($getRegistryInfo -eq $true){
    getRegistryInformation;
}