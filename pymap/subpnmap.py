#!/usr/bin/env python3

import re
import colorama
import subprocess
import argparse
from argparse import RawTextHelpFormatter

parser = argparse.ArgumentParser(formatter_class = RawTextHelpFormatter)
parser.add_argument('--selectscan', '-s', default = 0, help = """Options:
0: DEFAULT; Use for scanning all default ports
1: T3. No retries
2: Light Version Scan
3: Recursive DNS query
4: Traceroute
5: Vulnerability Script Scan
6: Firewall Statefullness""")
parser.add_argument('--flag', '-f', default = 0, help = '''
Flag Options:
0: -sS
1: -sA
2: -sF
3: -sW
4: -sM
5: -sU
6: -sC
7: -A''')
parser.add_argument('--sourceports', '-g', default = None, help = 'Enter source port.')
parser.add_argument('--port', '-p', default = None, help = 'Type acceptable port numbers. Same format accepted by nmap.')
parser.add_argument('--ip', '-i', help = 'Need IP address. Can also input a list of IPs.')
parser.add_argument('--dns', '-d', default = None, help = 'Enter file name with DNS IPs to resolve with.')
args = parser.parse_args()

def nmap(selectscan, flag, port, ip, dns, sp):
    flags = ('-sS', '-sA', '-sF', '-sW', '-sM', '-sU', '-sC', '-A')

    if port != None:
        p = f'-p{port}'
    else:
        p = None

    if sp != None:
        g = f'-g{sp}'
    else:
        g = None

    if str.isalpha(ip):
        print('Using list of IPs provided.')
        IP = ip
        ip = f'-iL {IP}'

    if int(selectscan) == 0:
        subprocess.run(f'sudo nmap -Pn -n --stats-every 1m --reason --max-retries 1 --min-rate 8 --max-rate 10 -T2\
        {flags[int(flag)]} {ip} {p} {g}', shell=True)
        #stdout = subprocess.PIPE)
    elif int(selectscan) == 1:
        subprocess.run(f'sudo nmap -Pn -n --packet-trace --reason --max-retries 0 {flags[int(flag)]} {ip} {p} {g}', shell=True)
        #stdout = subprocess.PIPE)
    elif int(selectscan) == 2:
        subprocess.run(f'sudo nmap -Pn -n --packet-trace --reason --max-retries 1 --version-light -sV {ip} {p} {g}', shell=True)
        #stdout = subprocess.PIPE)        
    elif int(selectscan) == 3:
        subprocess.run(f'sudo nmap -Pn -R --packet-trace --reason --max-retries 1 --min-rate 8 --max-rate 10 -T2 {flags[int(flag)]} {ip} {p} --dns-servers\
        {dns} {g}', shell=True)
    elif int(selectscan) == 4:
        subprocess.run(f'sudo nmap -Pn -n --traceroute --packet-trace --reason --max-retries 5 -sS {ip} {p} {g}', shell=True)
    elif int(selectscan) == 5:
        subprocess.run(f'sudo nmap -Pn -n --script vuln --reason {flags[int(flag)]} {ip} {p} {g}', shell=True)
    elif int(selectscan) == 6:
        o = port.split(',')
        openports = list(map(int, o))
        for element in list(range(1, 101)):
            if element in openports:
                openports.remove(element)
        if len(openports) == 0: exit(0) #return because if no open ports, no frame of reference
        else:
            hundredports = list(range(1,101 - len(openports))) + openports
            scanthese = ','.join(map(str, hundredports))
        subprocess.run(f'sudo nmap -Pn -n --reason -sS -p{scanthese} {ip}', shell=True)
        subprocess.run(f'sudo nmap -Pn -n --reason -sA -p{scanthese} {ip}', shell=True)

if __name__=='__main__':
    nmap(args.selectscan, args.flag, args.port, args.ip, args.dns, args.sourceports)
