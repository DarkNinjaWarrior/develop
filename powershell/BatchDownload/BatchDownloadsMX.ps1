#
# This script file relies on the PowerShell Script file BatchDownloads.ps1
#    and perform the multitasking.
#

$scriptblock = {
    Param($Task, $Path, $Scripts);
    &$Scripts -DownloadList $Task -DownloadPath $Path;
}

# Load the task list from the subfolder JobLists
# The job list files are the text files containing the URLs of the files to be downloaded (one URL per line)
$TaskLists = Get-ChildItem ".\JobLists";

# Get the current file path
$FilePath = (Get-Item -Path ".\").FullName;

# main script
foreach ($TaskList in $TaskLists){
    $jobTask = ""+$FilePath+"\JobLists\"+$TaskList;
    $scriptPath = ""+$FilePath+"\BatchDownloads.ps1";
    $destPath = ""+$FilePath+"\Downloads\";
    Start-Job -ScriptBlock $scriptblock -ArgumentList $jobTask, $destPath, $scriptPath;
}
Get-Job | Wait-Job | Receive-Job