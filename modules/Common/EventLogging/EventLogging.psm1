function EventLogging {
  Param (
      [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$false)]
      [System.String]
      $LogFile,
    
      [Parameter(Mandatory=$True, Position=1, ValueFromPipeline=$false)]
      [System.String]
      $EventMsg,
    
      [Parameter(Mandatory=$True, Position=2, ValueFromPipeline=$false)]
      [System.String]
      $Operation,
        
      [Parameter(Mandatory=$True, Position=3, ValueFromPipeline=$false)]
      [System.String]
      $LogLevel
  )

  $cTime = "["+(Get-Date).ToString('F')+"]";

  if ([System.IO.File]::Exists($LogFile)){
     $msg = $cTime+" ["+$LogLevel+"] "+$Operation+" - "+$EventMsg;
     $msg | Out-File $LogFile -Append;
  }
  else{
     $msg = $cTime+" ["+$LogLevel+"] "+$Operation+" - "+$EventMsg;
     $msg | Out-File $LogFile;
  }
}
Export-ModuleMember -Function EventLogging;