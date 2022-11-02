#!/usr/bin/env python3

#100 - len(openports) = hundredports ---> 
#list of 100 ports including open ones to check for statefulness of firewall
#remove ports in openarray that exist in hundredports
#subtract len of openarray from hundredports
#append hundredports with openarray elemnts

openports = [233, 231, 230]

for element in list(range(1, 101)):
    if element in openports:
        openports.remove(element)

if len(openports) == 0: exit(0) #return because if no open ports, no frame of reference
else:
    hundredports = list(range(1,101 - len(openports))) + openports
