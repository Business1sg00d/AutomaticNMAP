#!/usr/bin/env python3



import re
import colorama
import subprocess
import argparse
from argparse import RawTextHelpFormatter
from colorama import Fore, Back, Style



#openportsscan = sudo nmap -sS -g 53 -Pn -n --disable-arp-ping -p {newports} {args.ip}
#Create a method that creates a list of ports no greater than 100 total; subtract
#open ports from 100; remainder will be list plus open ports
#   100 - len(openports) = hundredports ---> hundredports = list(range(1,100 - len(openports)))
#


def filteredscan(filteredports):
    unfilteredarray = []
    filteredarray = []
    unfilteredports = subprocess.run(f'sudo nmap -sA -Pn -n --disable-arp-ping {filteredports} {args.ip}',\
    shell = True, capture_output = True)

    unfiltered = findport(unfilteredports)
    if len(unfiltered) != 0:
        for element in unfiltered:
            if element not in unfilteredarray:
                unfilteredarray.append(element)
        unfilteredports = ','.join(unfilteredarray)        
