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

#sS; if filtered no response || ICMP 3/3 <----actual syntax '(type=3/code=3)' 
#sA; if unfiltered from R || ICMP 3/3
#sF; and sX; if ICMP 3/3
#sM; if 'no response'
#sW; need to check window for >0 on known open port. If >0 w/ sS, but ==0 with sW, then unreliable

#shell = true allows commands that require the shell environment; only run with YOUR input

#p1 = subprocess.run(['ls', '-la', '|', 'grep', 'ss'], capture_output=True, text=True)
#if the 'shell' arguement is undesirable, then hard brackets are required around listed commands

#p1 = subprocess.run('sudo nmap -sS 127.0.0.1 -p-', shell=True, capture_output=True)
#capture stdout into a variable

#'capture_output = (stdout = subprocess.PIPE)* - stder'

#with open('writeme', 'w') as f:
#    p1 = subprocess.run('sudo nmap -sS 127.0.0.1 -p-', shell=True, stdout=f)
#writes output to file

#print(p1.args)
#shows arguments passed into subprocess variable p1

#print(p1.stdout)
#prints stdout from command
#In order to print traditional text to terminal, requires:
#   1.) run argument 'text=True', OR
#   2.) attach .decode() to print statement above like so
#       print(p1.stdout.decode())
#Why decode?

#print(p1.returncode)
#prints return code of last command
#description=textwrap.dedent('''\
#...         Please do not mess up this text!
#...         --------------------------------
#...             I have indented it
#...             exactly the way
#...             I want it
#...         ''))
#print(Fore.CYAN + 'Words') #prints Words in cyan
#print(Back.YELLOW + 'Words') #prints Words in yellow
#print(Style.RESET_ALL) #resets terminal color scheme to default
#colorama.init(autoreset=True) # resets color after each line
