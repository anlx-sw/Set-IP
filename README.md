# Set-IP

As I have to manually change network adapter settings quite often i wrote this powershell functions to be able to easily change adapter settings in "lazy" syntax (minimal typing).

I personally use conemu and load this function with my psprofile. For changing of adapter settings run powershell with admin privileges.
I run powershell v5 - but is think it should work with powershell >= v3.

## Usage expamples:

```sh
ip d 
```
or
``` sh
ip dhcp
```
to set adapter to dhcp or 
```sh 
ip <address> <subnetmask> <gateway> <dns1> <dns2>
```
to change the ip and use the first three octets of ip also for gateway and dns server:
```sh 
ip 192.168.100.40 24 254 1 2
```
or to set parameters in longer syntax for the wireless adpater
```sh
iw 192.168.100.40 255.255.255.0 192.168.100.254 192.168.100.1 192.168.100.2
```
or to show the ip settings of the ethernet adapter
```sh
ip 
```
or to show all ipv4 adapters
```sh
show-ip
```

There are two adpaters "LAN" and "WiFI" hardcoded to be used as ip or iw. You can change the adapter names in the "ip" and "iw" functions.

To be able to use the commands whenever powershell starts up you can add them in your powershell profile:

```sh
ise $profile
```
then add in your profile:
```sh
import-module -name .\path\to\set-ip.ps1
```



