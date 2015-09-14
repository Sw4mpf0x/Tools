#!/bin/bash
apt-get clean && apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y

rm /var/www/index.html
mkdir /root/tools
mkdir /var/www/rawr

#basic installs
apt-get install rdate
apt-get install python-setuptools
easy_install pip
pip install selenium
apt-get install unrar unace rar unrar p7zip zip unzip p7zip-full p7zip-rar file-roller -y

#Big gitlist
#
#mkdir /opt/gitlist/
#cd /opt/gitlist
#git clone https://github.com/macubergeek/gitlist.git
#cd gitlist
#chmod +x gitlist.sh
#./gitlist.sh

#msfconsole.rc
#
echo "spool /mylog.log" >> /msfconsole.rc
echo "set consolelogging true" >> /msfconsole.rc
echo "set loglevel 5" >> /msfconsole.rc
echo "set sessionlogging true" >> /msfconsole.rc
echo "set timestampoutput true" >> /msfconsole.rc
echo 'setg prompt "%cya%T%grn S:%S%blu J:%J "' >> /msfconsole.rc

#sipvicious

cd /root/tools
git clone https://github.com/sandrogauci/sipvicious.git

#Empire

cd /root/tools
git clone https://github.com/PowerShellEmpire/Empire.git
#run setup manually.

#Snarf

cd /root/tools
git clone https://github.com/purpleteam/snarf.git

#Veil-Evasion setup
#

pip install symmetricjsonrpc #needed for Kali 2.0
cd /root/tools
git clone https://github.com/Veil-Framework/Veil-Evasion.git
cd /root/tools/Veil-Evasion/setup
./setup.sh
cd /root/tools/Veil-Evasion/Veil-Catapult
./setup.sh

#Responder Setup
rm -r /usr/share/responder
rm /usr/bin/responder
cd /root/tools
git clone https://github.com/SpiderLabs/Responder.git
cd Responder
cp -r * /usr/bin

#Impacket Setup
cd /root/tools
git clone https://github.com/CoreSecurity/impacket.git
cd impacket
python setup.py install
cp /root/tools/impacket/examples/smbrelayx.py /usr/bin
chmod 755 /usr/bin/smbrelayx.py
cp /root/tools/impacket/examples/goldenPac.py /usr/bin
chmod 755 /usr/bin/goldenPac.py

#CG's gold_digger script {http://carnal0wnage.attackresearch.com/2015/02/my-golddigger-script.html}
#
mkdir -p /opt/carnal0wnage
cd /opt/carnal0wnage
git clone https://github.com/carnal0wnage/Metasploit-Code.git
cp /opt/carnal0wnage/Metasploit-Code/modules/post/windows/gather/gold_digger.rb /usr/share/metasploit-framework/modules/post/windows/gather

#Shell_Shocker Setup
cd /root/tools
git clone https://github.com/mubix/shellshocker-pocs.git

#RAWR Setup
cd /root/tools
git clone https://bitbucket.org/al14s/rawr.git
cd /root/tools/rawr
./install.sh

#PowerSploit Setup
cd /root/tools
git clone https://github.com/mattifestation/PowerSploit.git

#PowerTools Setup
cd /root/tools
git clone https://github.com/Veil-Framework/PowerTools.git
cp /root/tools/PowerTools/PowerUp/PowerUp.ps1 /var/www
cp /root/tools/PowerTools/PowerView/powerview.ps1 /var/www

#Pykek Setup
cd /opt
git clone https://github.com/bidord/pykek.git

#payload autogeneration
#
cd /root/tools
git clone https://github.com/trustedsec/unicorn.git

cd ~/Desktop
wget http://www.rarlab.com/rar/wrar520.exe
wine wrar520.exe
rm wrar520.exe

#foofus OWA enum scripts
#
mkdir -p /opt/foofus
cd /opt/foofus
wget http://www.foofus.net/jmk/tools/owa/OWALogonBrute.pl
wget http://www.foofus.net/jmk/tools/owa/OWA55EnumUsersURL.pl
wget http://www.foofus.net/jmk/tools/owa/OWALightFindUsers.pl
wget http://www.foofus.net/jmk/tools/owa/OWAFindUsers.pl
wget http://www.foofus.net/jmk/tools/owa/OWAFindUsersOld.pl

#Praeda install
# 
cd /root/tools
git clone https://github.com/percx/Praeda.git
git clone https://github.com/MooseDojo/praedasploit.git
cd praedasploit
mkdir -p /usr/share/metasploit-framework/modules/auxiliary/praedasploit
cp * /usr/share/metasploit-framework/modules/auxiliary/praedasploit
cpan -i LWP::Simple LWP::UserAgent HTML::TagParser URI::Fetch HTTP::Cookies IO::Socket HTML::TableExtract Getopt::Std  Net::SSL Net::SNMP NetAddr::IP

#setup sambe
mkdir /srv/kali
chmod 777 /srv/kali
echo "[kali]" >> /etc/samba/smb.conf
echo "        comment = Kali share" >> /etc/samba/smb.conf
echo "        path = /srv/kali" >> /etc/samba/smb.conf
echo "        browseable = yes" >> /etc/samba/smb.conf
echo "        public = yes" >> /etc/samba/smb.conf
echo "        writable = yes" >> /etc/samba/smb.conf
echo "        guest ok = yes" >> /etc/samba/smb.conf

msfupdate

apt-get clean && apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y
