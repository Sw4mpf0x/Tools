apt-get update
#cwd=$(pwd)
touch /var/www/ghostdriver.log
chmod 755 /var/www/ghostdriver.log
chown www-data /var/www/ghostdriver.log
#Setup Postgresql
service postgresql start
su postgres << 'EOF'
createdb BloodHound_db
psql -c "CREATE USER bloodhound WITH PASSWORD 'bloodhound' CREATEDB;"
psql -c 'GRANT ALL PRIVILEGES ON DATABASE "BloodHound_db" TO bloodhound;'
EOF


#Install PhantomJS
apt-get -y install python-requests python-m2crypto build-essential chrpath libssl-dev libxft-dev libfreetype6 libfreetype6-dev libfontconfig1 libfontconfig1-dev

PHANTOM_JS="phantomjs-1.9.8-linux-i686"

cd ~
export PHANTOM_JS="phantomjs-1.9.8-linux-i686"
wget https://bitbucket.org/ariya/phantomjs/downloads/$PHANTOM_JS.tar.bz2
tar xvjf $PHANTOM_JS.tar.bz2

mv $PHANTOM_JS /usr/local/share
ln -sf /usr/local/share/$PHANTOM_JS/bin/phantomjs /usr/local/bin
rm $PHANTOM_JS.tar.bz2

#Make BloodHound Directory

yes | cp -rf BloodHound/ /opt/BloodHound/


#start postgresql service at boot
#http://thecodeship.com/deployment/deploy-django-apache-virtualenv-and-mod_wsgi/
#https://www.digitalocean.com/community/tutorials/how-to-serve-django-applications-with-apache-and-mod_wsgi-on-ubuntu-14-04



#Install Python Virtual Environment
apt-get -y install python-pip python-dev build-essential libpq-dev
pip install --upgrade pip
pip install Django
pip install virtualenvwrapper
echo "export WORKON_HOME=$HOME/.virtualenvs" >> ~/.bash_profile
echo "source /usr/local/bin/virtualenvwrapper.sh" >> ~/.bash_profile
source ~/.bash_profile
cd /opt/BloodHound
mkvirtualenv BloodHound --no-site-packages
workon BloodHound
pip install psycopg2
pip install M2Crypto
#Install Django
pip install selenium
pip install Django
pip install Pillow==2.6.1 requests
./manage.py migrate
./manage.py makemigrations
./manage.py migrate

#Setup Python Virtual Environment
#echo "export WORKON_HOME=$HOME/.virtualenvs" >> ~/.bash_profile
#echo "source /usr/local/bin/virtualenvwrapper.sh" >> ~/.bash_profile
#source ~/.bash_profile
#cd /opt/BloodHound
#mkvirtualenv BloodHound --no-site-packages
#pip freeze > requirements.txt
#workon BloodHound
#for i in $(cat requirements.txt);do pip install $i;done
#pip install psycopg2

deactivate
#rm requirements.txt



#Setup Apache
apt-get -y install apache2 apache2.2-common apache2-mpm-prefork apache2-utils libexpat1 libapache2-mod-wsgi
service apache2 restart

echo "<VirtualHost *:8000>" >> /etc/apache2/sites-available/000-default.conf
echo "" >> /etc/apache2/sites-available/000-default.conf
echo "    Alias /static /opt/BloodHound/Web_Scout/static/" >> /etc/apache2/sites-available/000-default.conf
echo "    <Directory /opt/BloodHound/Web_Scout/static/Web_Scout/>" >> /etc/apache2/sites-available/000-default.conf
echo "        Require all granted" >> /etc/apache2/sites-available/000-default.conf
echo "    </Directory>" >> /etc/apache2/sites-available/000-default.conf
echo "" >> /etc/apache2/sites-available/000-default.conf
echo "    <Directory /opt/BloodHound/>" >> /etc/apache2/sites-available/000-default.conf
echo "        <Files wsgi.py>" >> /etc/apache2/sites-available/000-default.conf
echo "            Require all granted" >> /etc/apache2/sites-available/000-default.conf
echo "        </Files>" >> /etc/apache2/sites-available/000-default.conf
echo "    </Directory>" >> /etc/apache2/sites-available/000-default.conf
echo "    WSGIDaemonProcess BloodHound python-path=/opt/BloodHound:/root/.virtualenvs/BloodHound/lib/python2.7/site-packages" >> /etc/apache2/sites-available/000-default.conf
echo "    WSGIProcessGroup BloodHound" >> /etc/apache2/sites-available/000-default.conf
echo "    WSGIScriptAlias / /opt/BloodHound/BloodHound/wsgi.py" >> /etc/apache2/sites-available/000-default.conf
echo "" >> /etc/apache2/sites-available/000-default.conf
echo "</VirtualHost>" >> /etc/apache2/sites-available/000-default.conf
echo "listen 8000" >> /etc/apache2/ports.conf
service apache2 restart