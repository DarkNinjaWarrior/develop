#
#  IP Classes          IP Range                             Private IP Range
#  Class A             1.0.0.1 to 126.255.255.254           10.0.0.0 to 10.255.255.255
#  Class B             128.1.0.1 to 191.255.255.254         172.16.0.0 to 172.31.255.255
#  Class C             192.0.1.1 to 223.255.254.254         192.168.0.0 - 192.168.255.255
#  Class D             224.0.0.0 to 239.255.255.255         -
#  Class E             240.0.0.0 to 254.255.255.254         -
#

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]$Provider,
    [Parameter(Mandatory=$false)]$TokenKey,
    [Parameter(Mandatory=$false)]$IPStart,
    [Parameter(Mandatory=$false)]$IPEnd,
    [Parameter(Mandatory=$false)]$IPCount
)

# Global Variables
# Default Start Public IP Address
$_oct1 = 1;
$_oct2 = $_oct3 = $_oct4 = 0;
$_ipAddr = ""+$_oct1+"."+$_oct2+"."+$_oct3+"."+$_oct4+"";

# Other IP Address Parameters
$_ipStart = $_ipEnd = $null;
$_sOct1 = $_sOct2 = $_sOct3 = $_sOct4 = "";
$_eOct1 = $_eOct2 = $_eOct3 = $_eOct4 = "";

# Operation Parameters
$_count = 0;
$_quota = 0;
$_maxCount = 0;
$_ipCount = 0;
$_extUrl = "";

# Start and End IP Address
if (($IPStart -eq $null) -and ($IPEnd -ne $null)) {$_ipStart = $IPEnd;}
else {$_ipStart = $IPStart;}

if ($_ipStart -ne $null) {
    $_sOct1 = ([ipaddress]$_ipStart).GetAddressBytes()[0]; $_oct1 = $_sOct1;
    $_sOct2 = ([ipaddress]$_ipStart).GetAddressBytes()[1]; $_oct2 = $_sOct2;
    $_sOct3 = ([ipaddress]$_ipStart).GetAddressBytes()[2]; $_oct3 = $_sOct3;
    $_sOct4 = ([ipaddress]$_ipStart).GetAddressBytes()[3]; $_oct4 = $_sOct4;
}

if ($IPCount -ne $null) {$_ipEnd = $IPEnd;}
if ($_ipEnd -ne $null) {
    $_eOct1 = ([ipaddress]$_ipEnd).GetAddressBytes()[0];
    $_eOct2 = ([ipaddress]$_ipEnd).GetAddressBytes()[1];
    $_eOct3 = ([ipaddress]$_ipEnd).GetAddressBytes()[2];
    $_eOct4 = ([ipaddress]$_ipEnd).GetAddressBytes()[3];
}

$_ipAddrCnt = [math]::Pow(256,3)*($_eOct1-$_sOct1)+[math]::Pow(256,2)*($_eOct2-$_sOct2)+[math]::Pow(256,1)*($_eOct3-$_sOct3)+[math]::Pow(256,0)*($_eOct4-$_sOct4);
if ($_ipAddrCnt -lt 0) {$_ipAddrCnt =1;}


# IP GeoLocation Lookup Provider API Authentication Parameters
$_authDest = $Provider;
$_authParms = "";
$_authToken = $TokenKey;

# IP GeoLocation Lookup Provider Connection Parameters
if ($Provider -eq "ipstack") {$_extUrl = "http://api.ipstack.com";}
else {$_extUrl = "https://ipinfo.io";}

if ($TokenKey -gt $null) {
    if($Provider -eq "ipstack"){
        $_authParms="?access_key="+$TokenKey;
    }
    else{
        $_authParms="?token="+$TokenKey;
    }
}

if ($IPCount -gt 0){
    if ($_quota -eq 0) {
        if($_ipAddrCnt -gt 0) {$_maxCount = [math]::Min($IPCount,$_ipAddrCnt);}
        else {$_maxCount = $IPCount;}
    }
    else {
        if ($_ipAddrCnt -gt 0){$_maxCount = [math]::Min($IPCount,$_quota,$_ipAddrCnt);}
        else {$_maxCount = [math]::Min($IPCount,$_quota);}
    }
}

# Default IP Output
$_outPath = ".\IPGeoInfo";

# Main Scripts

# Prepair for the output files and folders
if (!(Test-Path $_outPath)) {New-Item -ItemType "directory" -Path $_outPath;}

#setIpAddr;

Try{
    Do{
    # Skip the Class A Private IP Ranges
    if ($_oct1 -eq 10) {
        $_oct1 = 11; $_oct2 = $_oct3 = $_oct4 = 0;
    }

    # Skip the local loopback IP Ranges
    if (($_oct1 -eq 127) -or (($_oct1 -eq 128) -and ($_oct2 -lt 1))){
        $_oct1 =128; $_oct2 =1; $_oct3 =0; $_oct4 =1;
    }

    # Skip the Automatic Private IP Ranges (APIPA)
    if (($_oct1 -eq 169) -and ($_oct2 -eq 254)) {
        $_oct1 =169; $_oct2=255; $_oct3 =0; $_oct4 =0;
    }

    # Skip the Class B Private IP Ranges
    if (($_oct1 -eq 172) -and (($_oct2 -ge 16) -and ($_oct2 -lt 32))) {
        $_oct1 =172; $_oct2 =32; $_oct3 =0; $_oct4 =0;
    }

    # Skip the Class C Private IP Ranges
    if (($_oct1 -eq 192) -and ($_oct2 -eq 168)) {
        $_oct1 =192; $_oct2=169; $_oct3 =0; $_oct4 =0;
    }

    # Set the current IP Address for Geolocation Search;
    $_ipAddr = ""+$_oct1+"."+$_oct2+"."+$_oct3+"."+$_oct4+"";
    #Write-Host $_ipAddr;
    
    #Lookup IP GeoLocation Information;
    $_url = $_extUrl+"/"+$_ipAddr+$_authParms;
	#Write-Host $_url;
    Invoke-WebRequest -Method Get -Uri $_url | ConvertFrom-Json | Select-Object | ConvertTo-Csv -NoTypeInformation | Set-Content $_outPath"\"$_ipAddr".csv";
    
    #Set the Next IP Address;
    $_oct4 += 1;
    if ($_oct4 -ge 256) {$_oct4 = 0;$_oct3+=1;}
    if ($_oct3 -ge 256) {$_oct3 = 0;$_oct2+=1;}
    if ($_oct2 -ge 256) {$_oct2 = 0;$_oct1+=1;}
    $_count+=1;
    }
    while (($_oct1 -ge 1) -and ($_oct1 -lt 224) -and ($_count -lt $_maxCount))
}
catch{
    if(!(Test-Path ".\Logs")) {New-Item -ItemType "directory" -Path ".\Logs";}
    Add-Content -Value $PSItem.ToString() -Path ".\Logs\iplookup_error.log";
}