#
#  IP Classes          IP Range                             Private IP Range
#  Class A             1.0.0.1 to 126.255.255.254           10.0.0.0 to 10.255.255.255
#  Class B             128.1.0.1 to 191.255.255.254         172.16.0.0 to 172.31.255.255
#  Class C             192.0.1.1 to 223.255.254.254         192.168.0.0 - 192.168.255.255
#  Class D             224.0.0.0 to 239.255.255.255         -
#  Class E             240.0.0.0 to 254.255.255.254         -
#

# Global Varioables
$_oct1 = 192; 
$_oct2 = 168;
$_oct3 = 0;
$_oct4 = 1;
$_ipAddr = "";
$_count = 0;


# Default IP GeoLocation Lookup Server (IPInfo.io)
$_extUrl = "https://ipinfo.io";
$_quota = 0;

# Default Authentication Tokens (IPInfo.io)
# $_authToken = "<Token_ID>";
$_authToken = $null;
$_authParms = "";

# Authentication Parameters (IPInfo.io)
if ($_authToken -eq $null) {$_authParms="";}
else {$_authParms = "?token="+$_authToken;}

# Default IP Output
$_outPath = ".\IPInfo";

# Shared Functions
function setIpAddr{
   $global:_ipAddr = ""+$global:_oct1+"."+$global:_oct2+"."+$global:_oct3+"."+$global:_oct4+"";
}

function nextIpAddr{
   $global:_oct4 += 1;
   if ($global:_oct4 -ge 256) {$global:_oct4 = 0;$global:_oct3+=1;}
   if ($global:_oct3 -ge 256) {$global:_oct3 = 0;$global:_oct2+=1;}
   if ($global:_oct2 -ge 256) {$global:_oct2 = 0;$global:_oct1+=1;}
   setIpAddr;
}

function ipInfoLookup{
    $_url = $global:_extUrl+"/"+$global:_ipAddr+$global:_authParms;
    Invoke-WebRequest -Method Get -Uri $_url | ConvertFrom-Json | Select-Object | ConvertTo-Csv -NoTypeInformation | Set-Content $global:_outPath"\"$global:_ipAddr".csv";
}
#
# Main Scripts

# Prepair for the output files and folders
if (!(Test-Path $_outPath)) {New-Item -ItemType "directory" -Path $_outPath;}


#for(($_oct1 -ge 1) -and ($_oct1 -lt 224) -and ($_count -lt 5)) {
Do{
  # Skip the Class A Private IP Ranges
  if ($_oct1 -eq 10) {
    $_oct1 = 11; $_oct2 = $_oct3 = $_oct4 = 0;
  }

  # Skip the local loopback IP Ranges
  if (($_oct1 -eq 127) -or (($_oct1 -eq 128) -and ($_oct2 -lt 1))){
    $_oct1 =128; $_oct2 =1; $_oct3 =0; $_oct4 =1;
  }

  # Skip the Class B Private IP Ranges
  if (($_oct1 -eq 172) -and (($_oct2 -ge 16) -and ($_oct2 -lt 32))) {
    $_oct1 =172; $_oct2 =32; $_oct3 =0; $_oct4 =0;
  }

  # Skip the Class C Private IP Ranges
  if (($_oct1 -eq 192) -and ($_oct2 -eq 168)) {
    $_oct1 =192; $_oct2 =169; $_oct3 =0; $_oct4 =0;
  }

  setIpAddr;
  ipInfoLookup;
  nextIpAddr;
  $_count+=1;
}
while (($_oct1 -ge 1) -and ($_oct1 -lt 224) -and (($_quota -eq 0) -or (($_quota -gt 0) -and ($_count -lt $_quota))))

