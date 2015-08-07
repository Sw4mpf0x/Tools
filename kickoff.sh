#/bin/bash
#Usage
display_usage(){
	clear
	echo "============================================================"
	echo "This script requires a 'working directory' to dump files to."
	echo ""
	echo "Usage: $0 /working/directory/"
	echo "============================================================"
}

if [ $# -le 0 ]
	then
		display_usage
		exit 0
fi

clear
echo "" > kickofflog.log
echo "" > report.txt
#Define logit Function. Logs whatever it is fed to 
logit(){
	echo "$(date +'%Y-%m-%d-%T') $1" >> $1kickofflog.log
}
report(){
	echo $1 >> $1report.txt
}

#Discovery Scan

echo -e "===================================="
echo -e "Beginning Discovery Scan"
echo -e "===================================="

report "Beginning Discovery Scan..."
logit "Start Discovery Scan"

nmap -sn -v10 -T4 -n --open -iL $1scope.txt --excludefile $1excludes.txt -oG $1ping-sweep —-stats-every 1m

report "Discovery scan has finished"
logit "Finished Discovery Scan"

#Create live host list (live-hosts.txt)
awk '/Up/{print $2}' $1ping-sweep |sort -u > $1live-hosts.txt
linecount=$(cat $1live-hosts.txt | wc -l)
report "There are $linecount hosts on the network."
read -p "Check that the exclusions were actually excluded and then press [Enter] to continue..."
#Builds a list of ports to scan in ports.txt

echo 445 > $1ports.txt
echo 21 >> $1ports.txt
echo 23 >> $1ports.txt
echo 25 >> $1ports.txt
echo 53 >> $1ports.txt
echo 389 >> $1ports.txt
echo 686 >> $1ports.txt
echo 1433 >> $1ports.txt
echo 2049 >> $1ports.txt
echo 3306 >> $1ports.txt
echo 5800,5900-5920 >> $1ports.txt
echo 5985 >> $1ports.txt #Rob Fuller/Chris Gates Dirty little secrets part 2. Psexec-winrm MSF module
echo 10000 >> $1ports.txt
echo 80 >> $1ports.txt

#Service Scan loop. Loops through and scans the list of services created above.

echo -e "===================================="
echo -e "Beginning Targetted Service Scans"
echo -e "===================================="

for port in $(cat $1ports.txt);
	do report "Scanning port $port";
	logit "Start Scanning port $port";
	nmap -Pn -p$port -sV -sC --open -T4 -oA $1$port -v10 --stats-every 1m -iL $1live-hosts.txt;
	logit "Finished Scanning port $port";
	report "Finished Scanning port $port" 
done

mkdir $1Finals

#list Telnet IPs minus printers
awk '!/telnet\?/ && !/print/ && !/printer/ && !/JetDirect/ && !/#/ && !/tcpwrapped/ && !/Ricoh/ && !/Up/ && !/APC/ && !/Pocket/' 23.gnmap | uniq > $1/Finals/TelnetList.gnmap
report "Telnet list created"

#SMTP Relay Nmap Script. 

echo -e "===================================="
echo -e "Beginning SMTP Open Relay"
echo -e "and Enumeration NSE scripts"
echo -e "===================================="

awk '!/printer/ && !/JetDirect/ && !/#/ && !/tcpwrapped/ && !/Ricoh/ && !/Up/ && !/APC/ && !/Pocket/{print $2}' 25.gnmap | uniq > smtprelay.txt

report "Checking for open relays"
logit "Start Open Relay Scan"
nmap -Pn --script smtp-open-relay.nse -p 25,465,587 --open -iL smtprelay.txt -oA $1Finals/SMTP_Relay
report "Finished Open Relay Scan"

report "Checking for SMTP user enumeration"
logit "Start Open Relay Scan"
nmap -Pn --script smtp-enum-users.nse -p 25,465,587 --open -iL smtprelay.txt -oA $1Finals/STMP_Enum
report "Finished Open Relay Scan"

rm smtprelay.txt

#HTTP(s) Screenshots


#List IPs that have 445 open and save as windows hosts?
awk '!/#/{print $2}' 445.gnmap | sort -u > 445.txt

echo -e "===================================="
echo -e "Beginning NFSulator"
echo -e "===================================="

#Tim Gamble's NFS script 
awk '!/#/{print $2}' 2049.gnmap | sort -u > nfs.txt
#!/bin/bash
ipfile=nfs.txt

### Delete Temp file
rm -f ./temp.txt 2>./error.log

### Create /tmp mountpoint
if [ ! -d /tmp/nfsmount ]; then
	mkdir -p /tmp/nfsmount
fi

### Checking and Showing open NFS shares

if [ -z "$ipfile" ]; then
	usage
else
	for i in `cat $ipfile` ; do showmount -e  $i | grep "/" | awk ' { print "'$i'"":"$1 }  ' >> temp.txt ; done
	for z in `cat ./temp.txt`  ; do umount /tmp/nfsmount 2>./error.log ; echo "Mounting $z" ; echo "Mount Command: mount -t nfs -o nolock $z /tmp/nfsmount" ; mount -t nfs -o nolock $z /tmp/nfsmount 2>./error.log ; ls -lah /tmp/nfsmount 2>./error.log ; echo "Un-Mounting $z" ; umount /tmp/nfsmount 2>./error.log ; echo -e "\n" ; done
	echo -e "Unmount Command: umount /tmp/nfsmount\n"
fi



rm -f ./temp.txt

read -p "Review the NFS shares above and then press [Enter] to continue..."


#VNC Brute Force

echo -e "===================================="
echo -e "Beginning VNC-Brute"
echo -e "===================================="

awk '!/#/{print $2}' 5800,5900-5920.gnmap | sort -u > $1Finals/vnc.txt
report "Brute forcing VNC"
logit "Start VNC-Brute scan"
nmap -Pn --open --script vnc-brute -p 5900-5920,5800 -iL $1Finals/vnc.txt -oA $1Finals/vnc
logit "Finished VNC-Brute scan"

#Check MSSQL for empty passwords

echo -e "===================================="
echo -e "Beginning MSSQL "
echo -e "===================================="

awk '/Up/{print $2}' 1433.gnmap |sort -u > 1433.txt
nmap --script ms-sql-empty-password -iL 1433.txt -oA $1Finals/mssql





