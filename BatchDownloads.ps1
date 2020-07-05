[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]$DownloadList,
    [Parameter(Mandatory=$false)]$DownloadPath
)

# default values of the parameters
$_downloadTargetList = ".\DownloadList.txt";
$_downloadTargetPath = ".\Downloads\";

# global variable settings
$downloadTargetList = $DownloadList;
$downloadTargetPath = $DownloadPath;

# control of the values of the global vairables
if ($DownloadList -eq $null) {$downloadTargetList = $_downloadTargetList;}
if ($DownloadPath -eq $null) {$downloadTargetPath = $_downloadTargetPath;}

# prepair the destination download path
if (!(Test-Path $downloadTargetPath)) {New-Item -ItemType "directory" -Path $downloadTargetPath;}

# load the task lists
$downloadList = Get-Content $downloadTargetList;

# main scripts
try{
    foreach ($downloadItem in $downloadList) {
        $downloadFileName = Split-Path $downloadItem -Leaf;
        $downloadFile = $downloadTargetPath+$downloadFileName;
        Invoke-WebRequest -uri $downloadItem -Method Get -OutFile $downloadFile;
    }
}
catch{
    if(!(Test-Path ".\Logs")) {New-Item -ItemType "directory" -Path ".\Logs";}
    Add-Content -Value $PSItem.ToString() -Path ".\Logs\batch_download_error.log";
}