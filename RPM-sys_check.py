#!/usr/bin/env python3

import os
import socket

t = os.popen('uptime').read()[:-1]
s = os.popen('df -h').read()[:-1]
x = os.popen('yum check-update | grep kernel').read()[:-1]
j = os.popen('cat /etc/os-release | grep VERSION=').read()[:-1]
y = os.popen('free -h').read()[:-1]
z = os.popen('yum updateinfo').read()[:-1]
b = os.popen('systemctl status sshd').read()[:-1]
d = os.popen('systemctl status ').read()[:-1]
e = os.popen('ps -eo pid,ppid,cmd,comm,%mem, --sort=-%mem | head -10').read()[:-1]
a = os.popen('ps -eo pid,ppid,cmd,comm,%cpu, --sort=-%cpu | head -10').read()[:-1]

print('**************************')
print('Server Hostname:')
print(socket.gethostname())
print('**************************')
print('Server OS:')
print(j)
print('**************************')
print('Server uptime:')
print(t)
print('**************************')
print('Server Disk space:')
print(s)
print('**************************')
print('Server Memory:')
print(y)
print('**************************')
print('Server pending kernel updates:')
print(x)
print('**************************')
print('Server updates:')
print(z)
print('**************************')
print('Sshd health check:')
print(b)
print('**************************')
print('Top 10 Memory processes:')
print(e)
print('**************************')
print('Top 10 Cpu processes:')
print(a)
print('**************************')
