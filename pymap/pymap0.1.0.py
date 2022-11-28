#!/usr/bin/env python3
#firewall function based on https://nmap.org/book/determining-firewall-rules.html
#Much more work to be done.



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
#prints ports found
#works with dns functions to return any open ports
def findport(scandata):
    infospace = str(scandata).split('\\n')
    prts = []
    del prts[:]
    for line in infospace:
        if len(line.strip()) == 0:
            continue
        starts = line[0]
        openonly = re.findall(r'\sopen\s', line.strip())
        unfilteredonly = re.findall(r'\sunfiltered\s', line.strip())
        if starts.isdigit() == True and len(openonly) != 0:
            newline = line.split('/')
            openport = re.findall(r'\d+', str(newline))
            prts.append(openport[0])
        elif starts.isdigit() == True and len(unfilteredonly) != 0:
            newline = line.split('/')
            unfilteredport = re.findall(r'\d+', str(newline))
            prts.append(unfilteredport[0])
        if starts.isdigit(): print(line.strip())
    return prts



#Parses data from allscan. Looks for filtered ports.
#Filtered ports are ammended to filteredports array
def findfiltered(allscan):
    str_allscan = str(allscan)
    parse_allscan = str_allscan.split('\\n')
    filteredports = []
    for line in parse_allscan:
        if len(line.strip()) == 0:
            continue
        starts = line[0]
        filteredonly = re.findall(r'\sfiltered\s', line.strip())
        printline = re.findall(r'\b\d+\/.*', line.strip())
        if starts.isdigit() == True and len(filteredonly) != 0:
            newline = line.split('/')
            filteredport = re.findall(r'\d+', str(newline))
            filteredports.append(filteredport[0])
    return filteredports



#works with firewall function
def findunfiltered(scandata):
    infospace = str(scandata).split('\\n')
    prts = []
    del prts[:]
    for line in infospace:
        if len(line.strip()) == 0:
            continue
        starts = line[0]
        unfilteredonly = re.findall(r'\sunfiltered\s', line.strip())
        if starts.isdigit() == True and len(unfilteredonly) != 0:
            newline = line.split('/')
            aport = re.findall(r'\d+', str(newline))
            prts.append(aport[0])
    return prts



#Looks for filtered from firewall enumeration
def ff(scandata):
    infospace = str(scandata).split('\\n')
    prts = []
    del prts[:]
    for line in infospace:
        if len(line.strip()) == 0:
            continue
        starts = line[0]
        filteredonly = re.findall(r'\sfiltered\s', line.strip())
        if starts.isdigit() == True and len(filteredonly) != 0:
            newline = line.split('/')
            aport = re.findall(r'\d+', str(newline))
            prts.append(aport[0])
    return prts



#finds and returns a list of open ports
def findopen(scandata):
    infospace = str(scandata).split('\\n')
    prts = []
    del prts[:]
    for line in infospace:
        if len(line.strip()) == 0:
            continue
        starts = line[0]
        openonly = re.findall(r'\sopen\s', line.strip())
        if starts.isdigit() == True and len(openonly) != 0:
            newline = line.split('/')
            aport = re.findall(r'\d+', str(newline))
            prts.append(aport[0])
    return prts



def hundred(ports):
    openports = list(map(int, ports))
    for element in list(range(1, 101)):
        if element in openports:
            openports.remove(element)
    hundredports = list(range(1,101 - len(openports))) + openports
    scanthese = ','.join(map(str, hundredports))
    return scanthese



#Extract ALL ports from initial scan
def parseports(firewallports):
    infospace = str(firewallports).split('\\n')
    prts = []
    for line in infospace:
        if len(line.strip()) == 0:
            continue
        starts = line[0]
        if starts.isdigit() == True:
            newline = line.split('/')
            p = re.findall(r'\d+', str(newline))
            prts.append(p[0])
    return prts



def firewall(portsreturned):
    p = hundred(parseports(portsreturned))
    print(' ')
    print(Fore.RED + '##########' + 'Enumerating firewall statefullness' + '##########')

    syn = subprocess.run(f'''
    sudo nmap -Pn -n --reason {args.ip} -p{p} -sS''', \
    shell=True, capture_output=True)

    if len(findopen(syn)) == 0:
        print(Fore.GREEN + 'No open ports')
        exit(0)

    ack = subprocess.run(f'''
    sudo nmap -Pn -n --reason {args.ip} -p{p} -sA''', \
    shell=True, capture_output=True)
    
    parseack = str(ack).split('\\n')
    allun = re.findall(r'100 unfiltered', str(parseack))

    parsesyn = str(syn).split('\\n')
    allfil = re.findall(r'100 filtered', str(parseack))

    if len(allun) != 0:
        print(Fore.GREEN + 'All ports provided returned unfiltered; 100% stateless')
        exit(0)
    elif len(allfil) != 0:
        print(Fore.GREEN + 'All ports returned filtered; Active firewall. 100% statefull with ports provided')
        exit(0)
    else:
        opSYN = findopen(syn)
        fiACK = ff(ack)
        unACK = findunfiltered(ack)
        if len(fiACK + unACK) == 0 and len(opSYN) != 0:     #if no filtered/unfiltered responses from ACK, nothing
            print(Fore.GREEN + 'Only OPEN ports found.')    #to show
            exit(0)

        if len(fiACK) == 0:             #I do this because sometimes filtered ports ONLY show in 'Not shown' result
            for elmnt in parseack:
                if 'Not shown' in elmnt: a = elmnt
                if 'a' in locals(): 
                    print(a + ' from ACK scan.')
                    break
            for elmnt in parsesyn:
                if 'Not shown' in elmnt: s = elmnt
                if 's' in locals():
                    print(s + ' from SYN scan.')
                    break

            if 's' and 'a' in locals(): print(Fore.RED + 'Firewall is active.')
            elif 's' and 'a' not in locals(): print(Fore.GREEN + 'No filtered ports found.')

            if len(unACK) == 0: 
                print('No unfiltered results returned.')
                exit(0)

            print(Fore.GREEN + 'Potentially stateless ports:')
            print(unACK)
            exit(0)
        else:
            print(' ')
            print(Fore.RED + '##########' + 'Following ports possibly stateful' + '##########')
            for elmnt in opSYN:
                if elmnt in fiACK:
                    print(elmnt)



def dns44380():
    n = 1
    while True:
        if n == 1:
            source = '-g 80'
            s80 = subprocess.run(f'''
            sudo nmap -sS -Pn -n --disable-arp-ping -p 53 {source} {args.ip}''', \
            shell=True, capture_output=True)
            isOpen = findport(s80)
        elif n == 2:
            source ='-g 443'
            s443 = subprocess.run(f'''
            sudo nmap -sS -Pn -n --disable-arp-ping -p 53 {source} {args.ip}''', \
            shell=True, capture_output=True)
            isOpen = findport(s443)
        n = n + 1
        if n > 2:
            break
        elif len(isOpen) > 0:
            print(' ')
            print(Fore.YELLOW + '##########' + Fore.GREEN + f'OPEN PORT 53/TCP with {source}' \
            + Fore.YELLOW + '##########')
            break
    udp53()



def udp53():
    n = 0 
    while True:
        if n == 0:
            sNorm = subprocess.run(f'''
            sudo nmap -sU -p 53 -Pn -n --disable-arp-ping {args.ip}''', \
            shell=True, capture_output=True)
            isOpen = findport(sNorm)
        elif n == 1:
            source = '-g 80'
            s80 = subprocess.run(f'''
            sudo nmap -sU -p 53 -Pn -n --disable-arp-ping {args.ip} {source}''', \
            shell=True, capture_output=True)
            isOpen = findport(s80)
        elif n == 2:
            source = '-g 443'
            s443 = subprocess.run(f'''
            sudo nmap -sU -p 53 -Pn -n --disable-arp-ping {args.ip} {source}''', \
            shell=True, capture_output=True)
            isOpen = findport(s443)
        n = n + 1
        if n > 2:
            break
        elif len(isOpen) > 0:
            if n != 1:
                print(' ')
                print(Fore.YELLOW + '##########' + Fore.GREEN + f'OPEN PORT 53/UDP with {source}' \
                + Fore.YELLOW + '##########')
                subprocess.run(f'''
                sudo nmap -sUV -p 53 -Pn -n --version-intensity 9 --script-trace --disable-arp-ping {args.ip} {source}''', \
                shell=True)
                break
            else:
                print(' ')
                print(Fore.YELLOW + '##########' + Fore.GREEN + f'OPEN PORT 53/UDP' \
                + Fore.YELLOW + '##########')
                subprocess.run(f'''
                sudo nmap -sUV -p 53 -Pn -n --version-intensity 9 --script-trace --disable-arp-ping {args.ip}''', \
                shell=True)
                break



def initialscan():
    print(' ')
    print(Fore.RED + '##########' + Fore.GREEN + 'Beginning scan on ALL ports!' \
    + Fore.RED + '##########')
    allscan = subprocess.run(f'''
    sudo nmap -sS -n -Pn --disable-arp-ping --min-rate 100 --stats-every 1m -p- {args.ip} --max-retries 2''', \
    shell = True, capture_output = True)
    return allscan



def versionscan(op):
    print(' ')
    print(Fore.RED + '##########' + Fore.GREEN + 'Beginning version scan on all OPEN ports!' \
    + Fore.RED + '##########')
    sVscan = subprocess.run(f'''
    sudo nmap -sV --version-intensity 9 -Pn -n {args.ip} -p {op} --reason --stats-every 1s 2> /dev/null
    ''', \
    shell = True, capture_output = True)
    sv = str(sVscan).split('\\n')
    for line in sv:
        if len(line) == 0:
            continue
        isport = line[0]
        if isport.isdigit() == True: print(line.strip())



def filteredscan(filteredports):
    unfilteredarray = []
    filteredarray = []
    unfilteredports = subprocess.run(f'''
    sudo nmap -sA -Pn -n --disable-arp-ping {filteredports} {args.ip}''', \
    shell = True, capture_output = True)
    unfiltered = findport(unfilteredports)
    if len(unfiltered) != 0:
        for element in unfiltered:
            if element not in unfilteredarray:
                unfilteredarray.append(element)
        unfilteredports = ','.join(unfilteredarray)        
    return unfilteredports



def source53scan(unfilteredports):
    print(' ')
    print(Fore.RED + '##########' + Fore.GREEN + 'Sourcing port 53 against filtered ports' \
    + Fore.RED + '##########')
    s53 = subprocess.run(f'''
    sudo nmap -sS -Pn -n --disable-arp-ping {unfilteredports} {args.ip} -g 53''', \
    shell = True, capture_output = True)
    if len(findport(s53)) == 0:
        print(Fore.GREEN + 'No open ports found with ' + Fore.BLUE + '-g 53')


#How to print ALL relevant info from script scan???
def main():
    allscan = initialscan()         #Scans ALL ports.
    p = findport(allscan)           #Returns any open ports
    if len(p) == 0:
        print(Fore.GREEN + 'No ports found or all filtered')
        exit(0)
    op = ','.join(p)
    versionscan(op)                 #Version scans all open ports
    fp = findfiltered(allscan)      #Searches for filtered ports from all port scan
    uf = filteredscan(fp)           #ACK scans filtered ports. RST responses returned.
    if len(fp) != 0: source53scan(uf)                #Sources port 53 in an attempt to get an open port
    if '53' in fp: dns44380()
    firewall(allscan)
    


if __name__=='__main__':
    main()
