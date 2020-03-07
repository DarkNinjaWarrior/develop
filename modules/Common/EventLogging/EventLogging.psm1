function EventLogging {
  Param (
      [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$false)]
      [System.String]
      $Path,
    
      [Parameter(Mandatory=$True, Position=1, ValueFromPipeline=$false)]
      [System.String]
      $Ops,
        
      [Parameter(Mandatory=$True, Position=2, ValueFromPipeline=$false)]
      [System.String]
      $EventMsg
  )

  $cTime = "["+(Get-Date).ToString('F')+"]";
  $LogFile = $Path+"\logs\events.log";

  if ([System.IO.File]::Exists($LogFile)){
     $msg = $cTime+" - "+$Ops+" - "+$EventMsg;
     $msg | Out-File $LogFile -Append;
  }
  else{
     $msg = $cTime+" - "+$Ops+" - "+$EventMsg;
     $msg | Out-File $LogFile;
  }
}
Export-ModuleMember -Function EventLogging;