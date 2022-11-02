#!/usr/bin/env python3



import re
import colorama
import subprocess
import argparse
from argparse import RawTextHelpFormatter
from colorama import Fore, Back, Style



colorama.init(autoreset=True)
parser = argparse.ArgumentParser(formatter_class = RawTextHelpFormatter)
parser.add_argument('--ip', '-i')
args = parser.parse_args()


#works with filteredFuntion to return unfilteredports ---> recieved RST flag
#works with dns functions to return any open ports
#takes all ports from allport scan to start filtering process <--- will cause issues of mixing port states in same
#array
def findport(scandata):             
    info = str(scandata)            
    infospace = info.split('\\n')
    prts = []
    del prts[:]
    for line in infospace:
        if len(line.strip()) == 0:
            continue
        starts = line[0]
        openonly = re.findall(r'\sopen\s', line.strip())
        #filteredonly = re.findall(r'\sfiltered\s', line.strip())
        unfilteredonly = re.findall(r'\sunfiltered\s', line.strip())
        if starts.isdigit() == True and len(openonly) != 0:
            newline = line.split('/')
            openport = re.findall(r'\d+', str(newline))
            prts.append(openport)
            #print(newline)
        #elif starts.isdigit() == True and len(filteredonly) != 0: 
            #newline = line.split('/')
            #filteredport = re.findall(r'\d+', str(newline))
            #prts.append(filteredport)
            #print(newline)
        elif starts.isdigit() == True and len(unfilteredonly) != 0:
            newline = line.split('/')
            unfilteredport = re.findall(r'\d+', str(newline))
            prts.append(unfilteredport)
            #print(newline)
    return prts



def dns44380():
    n = 1
    while True:
        if n == 1:
            source = '-g 80'
            s80 = subprocess.run(f'sudo nmap -sS -Pn -n --disable-arp-ping -p 53 {source} {args.ip}', shell=True, capture_output=True)
            isOpen = findport(s80)
        elif n == 2:
            source ='-g 443'
            s443 = subprocess.run(f'sudo nmap -sS -Pn -n --disable-arp-ping -p 53 {source} {args.ip}', shell=True, capture_output=True)
            isOpen = findport(s443)
        n = n + 1
        if n > 2:
            break
        elif len(isOpen) > 0:
            print(Fore.YELLOW + '##########' + Fore.GREEN + f'OPEN PORT 53/TCP with {source}' + Fore.YELLOW + '##########')
            break
    udp53()



def udp53():
    n = 0 
    while True:
        if n == 0:
            sNorm = subprocess.run(f'sudo nmap -sU -p 53 -Pn -n --disable-arp-ping {args.ip}', shell=True, capture_output=True)
            isOpen = findport(sNorm)
        elif n == 1:
            source = '-g 80'
            s80 = subprocess.run(f'sudo nmap -sU -p 53 -Pn -n --disable-arp-ping {args.ip} {source}', shell=True, capture_output=True)
            isOpen = findport(s80)
        elif n == 2:
            source = '-g 443'
            s443 = subprocess.run(f'sudo nmap -sU -p 53 -Pn -n --disable-arp-ping {args.ip} {source}', shell=True, capture_output=True)
            isOpen = findport(s443)
        n = n + 1
        if n > 2:
            break
        elif len(isOpen) > 0:
            if n != 1:
                print(Fore.YELLOW + '##########' + Fore.GREEN + f'OPEN PORT 53/UDP with {source}' + Fore.YELLOW + '##########')
                subprocess.run(f'sudo nmap -sUV -p 53 -Pn -n --version-intensity 9 --script-trace --disable-arp-ping {args.ip} {source}', shell=True)
                break
            else:
                print(Fore.YELLOW + '##########' + Fore.GREEN + f'OPEN PORT 53/UDP' + Fore.YELLOW + '##########')
                subprocess.run(f'sudo nmap -sUV -p 53 -Pn -n --version-intensity 9 --script-trace --disable-arp-ping {args.ip}', shell=True)
                break



def main():
    dns44380()



if __name__=='__main__':
    main()



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
#...         '''))
#print(Fore.CYAN + 'Words') #prints Words in cyan
#print(Back.YELLOW + 'Words') #prints Words in yellow
#print(Style.RESET_ALL) #resets terminal color scheme to default
#colorama.init(autoreset=True) # resets color after each line
