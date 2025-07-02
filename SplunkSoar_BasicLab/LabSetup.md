## **Used Resources:**



***Splunk SOAR VM (Ubuntu)***



***Windows Server 2022 Core (headless, no GUI)***



***Splunk Universal Forwarder (for log shipping)***







### Part 1: Initial Configuration





##### **Windows 2022 Setup (Assuming installed and ready to go):**







&nbsp;	First, we need to make sure PowerShell Remoting is enabled



&nbsp;		*Enable-PSRemoting -Force*





&nbsp;	Now, we will manually add the firewall rule to allow WinRM, for powershell RM to work correctly.



		*New-NetFirewallRule -Name "AllowWinRM" -DisplayName "Allow WinRM" -Protocol TCP -LocalPort 5985 -Direction Inbound -Action Allow*



&nbsp;	

&nbsp;	To verify this was created successfully upon creation, simply run 

&nbsp;	

&nbsp;		*Get-NetFirewallRule AllowWinRM*





&nbsp;	NOTE, since we are not using a domain, we must set our own trusted host, in this case, since our Splunk client is not setup, we will set 	a temporary \* value.





		*Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value "\*" -Force*





&nbsp;	Now we can verify the listener with the following command,



		*winrm enumerate winrm/config/listener*





&nbsp;	If the final line reads "ListeningON = x.x.x.x, 127.0.0.1 ::1.... it was setup correctly!



#### 

#### **SOAR UBUNTU SETUP**















