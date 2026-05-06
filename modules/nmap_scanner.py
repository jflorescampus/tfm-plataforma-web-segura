# Nmap 7.94 scan initiated — Target: 192.168.20.10
# Command: nmap -sV -sC -T4 -p 1-65535 --script vuln,ssl-cert,ssh-auth-methods 192.168.20.10

Nmap scan report for 192.168.20.10
Host is up (0.00042s latency).

PORT      STATE  SERVICE  VERSION
22/tcp    open   ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-auth-methods:
|   Supported authentication methods:
|     publickey
|_    password                         ← HALLAZGO HIGH: acepta contraseñas

80/tcp    open   http     Apache httpd 2.4.52 ((Ubuntu))
| http-headers:
|   Server: Apache/2.4.52 (Ubuntu)    ← versión expuesta en cabecera
|_  (Request type: HEAD)

443/tcp   closed https

3306/tcp  open   mysql    MySQL 8.0.36-0ubuntu0.22.04.1
|_  [HALLAZGO HIGH: MySQL accesible desde red externa]

33060/tcp open   mysqlx?

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

