param(
$path
)
#$path="C:\Users\ACRS\Desktop"
$new_path=$path+"\ip_address.csv"
echo($new_path)
Update-DnsServerTrustPoint -Force
gpupdate /force
Get-ADComputer -Filter * -Property * | Select-Object DNSHostName,OperatingSystem,ipv4Address,OperatingSystemVersion,OperatingSystemServicePack | Export-Csv $new_path

(Get-Content $new_path | Select-Object -Skip 2 )| Set-Content $new_path
