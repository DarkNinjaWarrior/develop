$getRunningServices = $true;
$getRunningProcesses = $true;
$getFileSystemInfo = $true;
$getRegistryInfo = $true;

$currentLocation = Get-Location;

$dirRootListFile = ""+$currentLocation+"\directory_list.txt";
$regRootListFile = ""+$currentLocation+"\registry_list.txt";

$reportRunningService = ""+$currentLocation+"\Running_Services.txt";
$reportRunningProcess = ""+$currentLocation+"\Running_Processes.txt";
$reportFireDirProperty = ""+$currentLocation+"\directory_property.txt";
$reportFireDirACL = ""+$currentLocation+"\directory_acl.txt";
$reportRegistryProperty = ""+$currentLocation+"\registry_property.txt";
$reportRegistryACL = ""+$currentLocation+"\registry_acl.txt";

if ((Test-Path $reportRunningService) -eq $true) {Remove-Item -Path $reportRunningService -Force;}
if ((Test-Path $reportRunningProcess) -eq $true) {Remove-Item -Path $reportRunningProcess -Force;}
if ((Test-Path $reportFireDirProperty) -eq $true) {Remove-Item -Path $reportFireDirProperty -Force;}
if ((Test-Path $reportFireDirACL) -eq $true) {Remove-Item -Path $reportFireDirACL -Force;}
if ((Test-Path $reportRegistryProperty) -eq $true) {Remove-Item -Path $reportRegistryProperty -Force;}
if ((Test-Path $reportRegistryACL) -eq $true) {Remove-Item -Path $reportRegistryACL -Force;}


if ($getRunningServices -eq $true){
    Get-Service * | ConvertTo-Json | Out-File $reportRunningService
}

if ($getRunningProcesses -eq $true){
    Get-Process * | ConvertTo-Json | Out-File $reportRunningProcess 
}

if($getFileSystemInfo -eq $true){
   $dirRootList = Get-Content $dirRootListFile
   foreach ($dirList in $dirRootList){
       $actionItem = Get-ChildItem -Path $dirList -Recurse
       $actionItem | ForEach-Object -Begin $null -Process {Get-ItemProperty $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl | ConvertTo-Json | Out-File -append $reportFireDirProperty },{Get-Acl $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl | ConvertTo-Json | Out-File -append $reportFireDirACL } -End $null
   }
}

if($getRegistryInfo -eq $true){
   $regRootList = Get-Content $regRootListFile
   foreach ($regList in $regRootList){
       $actionItem = Get-ChildItem -Path Registry::$regList -Recurse
       $actionItem | ForEach-Object -Begin $null -Process {Get-ItemProperty $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider | ConvertTo-Json | Out-File -append $reportRegistryProperty },{Get-Acl $_.PsPath | Select-Object -Property * -ExcludeProperty PSDrive,PSProvider,AccessRightType,AccessRuleType,AuditRightType,AuditRuleType,Sddl | ConvertTo-Json | Out-File -append $reportRegistryACL } -End $null
   }
}