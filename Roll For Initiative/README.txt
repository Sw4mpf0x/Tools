Roll For Initiative is a tool for kicking of your security assessment.

Setup:
1. Place both scripts in the same location
2. Run RFI.py
3. You will be presented with a menu to select from. Below is a description of the menu items

Usage:
When running, RFI is going to ask for a client name. This name will be used to create a client folder at '/root/Clients/[client name]'. Next, RFI is going to look for 'scope.txt' and 'excludes.txt' files in that client folder, with 'scope.txt' containing the ranges you want to scan and 'excludes.txt' containing anything that should not be scanned. The 'excludes.txt' file must exist, even if it is empty. Lastly, RFI will want you to confirm the log file to be use. Hit enter for the default. In this log file you will find timestamps for each scan done within RFI. 

Menu:
1. Kickoff scan - This is going to do a number of scans and parse some of those scans into useful files. 
		a) Ping-sweep. Uses the 'scope.txt' and 'excludes.txt' to build a live host lists that is parsed into 'live-hosts.txt'. RFI will pause after the ping sweep so you can check your live host list. Hit enter when finished.
		b) Targeted port scans. The following ports are scanned for version information and create applicable Nmap, Gnmap, and XML files: 22, 23, 53, 389, 686, 2049, 5800,5900-5920, 5985, 10000. The following ports are scanned for version info and applicable NSE scripts are used: 445, 21, 25, 1433, 3306, 80. 
		c) A list of non-printer hosts with telnet open is parsed into '/root/Clients/[client name]/Finals/TelnetList.txt'.
		d) A list of hosts with port 445 open is parsed into 445.txt.
		e) Hosts with port 25 open are scanned for SMTP enumeration and open relay. Results are exported to '/root/Clients/[client name]/Finals/'.
2. Rawr Scan - Nmap is used to scan each host for the following ports: 80,280,443,591,593,981,1311,2031,2480,3181,4444,4445,4567,4711,4712,5104,5280,7000,7001,7002,8000,8008,8011,8012,8013,8014,8042,8069,8080,8081,8243,8280,8281,8443,8531,8887,8888,9080,9443,11371,12443,16080,18091,18092. The resultant XML file is fed into Rawr. A folder start with 'log' will be dropped in the client folder with the Rawr results. 
3. Service Scan - Scans for the top 1000 ports with Nmap. Exports Nmap, Gnmap, and XML.
4. Pentest Setup - Takes an IP address that it uses for LHOST. Creates TCP and HTTPS Veil and Unicorn payloads and drops them at '/root/' and '/var/www/html'. A Metasploit resource script named 'bounce' is placed in the root directory. When ran it will setup handlers for the TCP and HTTPS payloads. An html file is placed at '/var/www/html/cmd.html' that includes Powershell cmdlet download cradles with the supplied IP address.