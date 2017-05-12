function ip 
{
$adaptername = "LAN"
if ($args)
{
    if (Test-isAdmin)
    { 
    Set-IP $adaptername $args[0] $args[1] $args[2] $args[3] $args[4]
    }
    else
    {
    write-host "Please run with admin rights to change network settings."
    }
}
else
{
Show-IP $adaptername
}

}

function iw
{
$adaptername = "WiFi"
if ($args)
{
    if (Test-isAdmin)
    { 
    Set-IP $adaptername $args[0] $args[1] $args[2] $args[3] $args[4]
    }
    else
    {
    write-host "Please run with admin rights to change network settings."
    }
}
else
{
Show-IP $adaptername
}

}


function Test-isAdmin {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Set-IP {

param([Parameter(Mandatory=$true)]$adaptername, [Parameter(Mandatory=$true)]$Address, $Subnetmask, $Gateway, $Dns1 ,$Dns2)

$usagetext = 
"Syntax Error - Usage:
======================================================================================
'ip d' or 'ip dhcp' to set adapter to dhcp
-- or -- 
ip <address> <subnetmask> <gateway> <dns1> <dns2>

example:
ip 192.168.100.40 24 254 1 2
or
Set-IP 192.168.100.40 255.255.255.0 192.168.100.254 192.168.100.1 192.168.100.2
======================================================================================
"
#check if first param is keyword d or dhcp or if it is a valid ip
if (($Address -eq "d") -or ($Address -eq "dhcp"))
{
Configure-AdapterToDhcp $adaptername
}
else
{
    Try
    {
        $ip = [System.Net.IPAddress]$Address
    }
    Catch
    {
       throw $usagetext
    }


if ($Subnetmask)
{
    if ($Subnetmask -in 0..32)
    {
	#Convert subnetmask param in prefix form to subnetmask string
    $Subnetmask = $(Convert-Mask -PrefixLength $Subnetmask).Subnetmask
    }
    else
    {
        Try
        {
            $Subnetmask = [System.Net.IPAddress]$Subnetmask
        }
        Catch
        {
            throw $usagetext
        }
    }

}

if ($Gateway)
{
    if ($Gateway -in 0..255)
    {
    $Gateway = replace-lastoctet $Address $Gateway
    }
    else
    {
        Try
        {
            $Gateway = [System.Net.IPAddress]$Gateway
        }
        Catch
        {
            throw $usagetext
        }
    }

}


if ($Dns1)
{
    if ($Dns1 -in 0..255)
    {
    $Dns1 = replace-lastoctet $Address $Dns1
    }
    else
    {
        Try
        {
            $Dns1 = [System.Net.IPAddress]$Dns1
        }
        Catch
        {
            throw $usagetext
        }
    }

}

if ($Dns2)
{
    if ($Dns2 -in 0..255)
    {
    $Dns2 = replace-lastoctet $Address $Dns2
    }
    else
    {
        Try
        {
            $Dns2= [System.Net.IPAddress]$Dns2
        }
        Catch
        {
            throw $usagetext
        }
    }

}

configure-adapter $adaptername $Address $Subnetmask $Gateway $Dns1 $Dns2

}
}


function Replace-Lastoctet
{
param (
 [System.Net.IPAddress]$ip,
 
 [ValidateRange(0,255)]
 [int]$newoctet
)
 $octets = $ip.IPAddressToString -split "\."
 $octets[3] = $newoctet.ToString() 
$newaddress = $octets -join "."
return [IPAddress]$newaddress

}


function Convert-Mask {

param( 

    [Parameter(ParameterSetName="SubnetMask",Mandatory=$True)][string]$SubnetMask, 
    [Parameter(ParameterSetName="PrefixLength",Mandatory=$True)][int]$PrefixLength)


####################################
#User provided a prefix
if ($PrefixLength)
{
    $PrefixLengthReturn = $PrefixLength
    if ($PrefixLength -gt 32) 
    { 
        write-host "Invalid input, prefix length must be less than 32"
      #  exit(1)
    }
               
    $bitArray=""
    for($bitCount = 0; $PrefixLength -ne "0"; $bitCount++) 
    {
        $bitArray += '1'
        $PrefixLength = $PrefixLength - 1;
    }
    
    ####################################                       
    #Fill in the rest with zeroes
    While ($bitCount -ne 32) 
    {
        $bitArray += '0'
        $bitCount++ 
    }
    ####################################
    #Convert the bit array into subnet mask
    $ClassAAddress = $bitArray.SubString(0,8)
    $ClassAAddress = [Convert]::ToUInt32($ClassAAddress, 2)
    $ClassBAddress = $bitArray.SubString(8,8)
    $ClassBAddress = [Convert]::ToUInt32($ClassBAddress, 2)
    $ClassCAddress = $bitArray.SubString(16,8)
    $ClassCAddress = [Convert]::ToUInt32($ClassCAddress, 2)
    $ClassDAddress = $bitArray.SubString(24,8)           
    $ClassDAddress = [Convert]::ToUInt32($ClassDAddress, 2)
 
    $SubnetMaskReturn =  "$ClassAAddress.$ClassBAddress.$ClassCAddress.$ClassDAddress"
}

####################################
##User provided a subnet mask
if ($SubnetMask)
{
	####################################
    #Ensure valid IP address input.  Note this does not check for non-contiguous subnet masks!
    $Address=[System.Net.IPaddress]"0.0.0.0"
    Try
    {
        $IsValidInput=[System.Net.IPaddress]::TryParse($SubnetMask, [ref]$Address)
    }
    Catch 
    {

    }
    Finally
    {

    }    

    if ($IsValidInput -eq $False)
    {
        Write-Host "Invalid Input. Please enter a properly formatted subnet mask."
      #  Exit(1)
    }

    ####################################
    #Convert subnet mask to prefix length
    If($IsValidInput)
    {
        $PrefixArray=@()
        $PrefixLength = 0
        $ByteArray = $SubnetMask.Split(".")
        
        ####################################        
        #This loop converts the bytes to bits, add zeroes when necessary
        for($byteCount = 0; $byteCount-lt 4; $byteCount++) 
        {
            $bitVariable = $ByteArray[$byteCount]
            $bitVariable = [Convert]::ToString($bitVariable, 2)
            
            if($bitVariable.Length -lt 8)
            {
              $NumOnes=$bitVariable.Length
              $NumZeroes=8-$bitVariable.Length

              for($bitCount=0; $bitCount -lt $NumZeroes; $bitCount++) 
              {
                $Temp=$Temp+"0"
              }
              
              $bitVariable=$Temp+$bitVariable
            }
            
            ####################################
            #This loop counts the bits in the prefix
            for($bitCount=0; $bitCount -lt 8; $bitCount++) 
            {
                if ($bitVariable[$bitCount] -eq "1")
                {
                    $PrefixLength++ 
                }

                $PrefixArray=$PrefixArray + ($bitVariable[$bitCount])

            }
        }
        
        ####################################
        #Check if the subnet mask was contiguous, fail if it wasn't.
        $Mark=$False

        foreach ($bit in $PrefixArray) 
        {
            if($bit -eq "0")
            {
                if($Mark -eq $False)
                {
                    $Mark=$True
                }
            }
            if($bit -eq "1")
            {
                if($Mark -eq $True)
                {
                    Write-Host "Invalid Input. Please enter a properly formatted subnet mask."
                #    Exit(1)
                }    
            }
       }

	    $SubnetMaskReturn = $SubnetMask
	    $PrefixLengthReturn = $PrefixLength
	}
}
##Create the object to be returned to the console
$Return = new-object Object
Add-Member -InputObject $Return -Name PrefixLength -Value $PrefixLengthReturn -Type NoteProperty
Add-Member -InputObject $Return -Name SubnetMask -Value  $SubnetMaskReturn -Type NoteProperty
$Return
}              

function Show-IP
{
param (
$adaptername
)

if ($adaptername) {
Get-NetIPConfiguration -InterfaceAlias $adaptername -Detailed | 
Select InterfaceAlias,
@{N="Status";E={$_.NetAdapter.Status}},
@{N="IP";E={"$($_.IPv4Address.IPv4Address)/$($_.IPv4Address.PrefixLength)"}}, 
@{N="DefaultGateway";E={$_.IPv4DefaultGateway.nexthop}}, 
@{N="MAC";E={$_.NetAdapter.MACAddress}}, 
@{N="DHCP";E={$_.NetIPv4Interface.DHCP}}, 
@{N="DNS";E={ ($_.DNSServer | where {$_.AddressFamily -eq 2} | select -ExpandProperty ServerAddresses) -join ","}} | fl 
}
else
{
Get-NetIPConfiguration  -Detailed | 
Select InterfaceAlias,
@{N="Status";E={$_.NetAdapter.Status}},
@{N="IP";E={"$($_.IPv4Address.IPv4Address)/$($_.IPv4Address.PrefixLength)"}}, 
@{N="DefaultGateway";E={$_.IPv4DefaultGateway.nexthop}}, 
@{N="MAC";E={$_.NetAdapter.MACAddress}}, 
@{N="DHCP";E={$_.NetIPv4Interface.DHCP}}, 
@{N="DNS";E={ ($_.DNSServer | where {$_.AddressFamily -eq 2} | select -ExpandProperty ServerAddresses) -join ","}} | ft
}

}


function Configure-Adapter
{
param (
$adaptername,$Address, $Subnetmask, $Gateway, $Dns1, $Dns2
)

write-host "Old Adapter Settings:"
Show-IP $adaptername

$Subnetmask = $(Convert-Mask -SubnetMask $Subnetmask).PrefixLength

If ($interface.Dhcp -eq "Enabled") 
{
Set-NetIPInterface -DHCP Disabled -InterfaceAlias $adaptername
}

Remove-NetIPAddress -InterfaceAlias $adaptername -AddressFamily IPv4 -confirm:$false 
Remove-NetRoute -InterfaceAlias $adaptername -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0 -confirm:$false

if ($Gateway)
{
New-NetIPAddress  -InterfaceAlias $adaptername -AddressFamily IPv4  -IPAddress $Address -PrefixLength $Subnetmask -DefaultGateway $Gateway -confirm:$false | out-null
}
else
{
New-NetIPAddress  -InterfaceAlias $adaptername  -IPAddress $Address -PrefixLength $Subnetmask  -confirm:$false 
}




if ($Dns2)
{
Set-DNSClientServerAddress -InterfaceAlias $adaptername  -ServerAddresses $Dns1, $Dns2 
}
elseif ($Dns1)
{

Set-DNSClientServerAddress -InterfaceAlias $adaptername  -ServerAddresses $Dns1
}
sleep 2
write-host "New Adapter Settings:"
Show-IP $adaptername
}


function Configure-AdapterToDhcp
{
param (
[Parameter(Mandatory=$true)]$adaptername
)
write-host "Old Adapter Settings:"
Show-IP $adaptername

$IPType = "IPv4"
$interface =  Get-NetIPInterface -AddressFamily $IPType -interfaceAlias $adaptername
If ($interface.Dhcp -eq "Disabled") {
 # Remove existing gateway
 If (($interface | Get-NetIPConfiguration).Ipv4DefaultGateway) {
Remove-NetRoute -InterfaceAlias $adaptername -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0 -confirm:$false
 }
 # Enable DHCP
 $interface | Set-NetIPInterface -DHCP Enabled
 # Configure the DNS Servers automatically
 $interface | Set-DnsClientServerAddress -ResetServerAddresses
}
sleep 2
write-host "New Adapter Settings:"
Show-IP $adaptername

}