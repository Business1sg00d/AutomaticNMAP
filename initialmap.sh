#!/bin/bash
###GOAL: Automatically seek open ports by performing sequence of scans to bypass firewall
###save a list of open ports to comeback to 
###At the end of scan; list open ports with their services
###Give user the option to perform enumeration scans/vuln scans
###allport scan; grep script if open write to OPEN file; if filtered write to FILTERED file
###Perform service scans on open; write port / service / service version and output
###Perform filterscans to find open port through sourcedns



#Text Colors
#txtred="\e[91;1m"
txtrst="\e[0m"
txtred="\e[0;31m"
txtyel="\e[;33m"
txtblue="\e[0;34m"
txtgreen="\e[0;32m"
txtwhite="\e[0;37"
#Black        0;30
#Red          0;31
#Green        0;32
#Yellow       0;33
#Blue         0;34
#Purple       0;35
#Cyan         0;36
#White        0;37
#Reset Text Color   0m


#using sudo in order to use subsequent scans under root privileges
sudo clear
echo "Enter IP" ; read ip ; touch openports ; touch filteredports ; clear


#This check is used to determine if a port is open; if it is, that port is written to a file, and '2' is returned. 
#The file 'autoscan' is wiped in order to avoid false positives/errors involving open ports in previous scans
function opencheck() {
	state=$(cat autoscan | grep [/][ut][dc][p] | cut -d" " -f2 | grep -w open | sort -u)
	[[ -n $state ]] && [[ $state =~ ^[f][i][l][t][e][r][e][d]$ ]] && $(cat autoscan | grep -w filtered >> filteredports)
	[[ -n $state ]] && [[ $state =~ ^[o][p][e][n]$ ]] && $(cat autoscan | grep -w open >> openports) && cp /dev/null autoscan && return 2
	cp /dev/null autoscan
}


#Similar to above, but looks for a reset flag in packets, then returns a 2
function Rcheck() {
	R=$(cat autoscan | grep -w "TCP" | grep -w -o "R" | sort -u) ; [[ -z $R ]] && echo "No reset flag."
	[[ $R = R ]] && cp /dev/null autoscan && return 2
	cp /dev/null autoscan
}



function synscan() {
	sudo nmap -sS -n -Pn --disable-arp-ping -p $port $ip >> autoscan --packet-trace 
}



function ackscan() {
	sudo nmap -sA -Pn -n --disable-arp-ping -p $port $ip >> autoscan --packet-trace && Rcheck
}



function dns44380() {
	###Performs enumeration on standard DNS port 53. Looks for open port with SYN scan. If not open via opencheck function, looks for R(Reset) flag with ACK scan. If R flag is recieved without an ACK, it can be assumed
	###that the port is active, but behind a Firewall. At this point a UDP scan is executed to find if 53/udp is open(see 53Udp function below).
	###The process explained above is repeated with source ports 80 and 443; all in order to find port 53 open for either UDP or TCP. 
	###If ACK scan yielded a R(Reset) response from target(showing unfiltered state), BUT THEN shows filtered state as function continues, it can be assumed the IPS has blocked your IP. Try manual enumeration using different IP.
	echo ; echo "Performing ACK scan on port 53..." ; sudo nmap -sA -Pn -n --disable-arp-ping -p 53 $ip --packet-trace >> autoscan && Rcheck ; [[ $? = 2 ]] && 53Udp
	echo ; echo "Performing SYN scan on port 53..." ; sudo nmap -sS -Pn -n --disable-arp-ping -p 53 $ip --packet-trace --source-port 80 >> autoscan && opencheck ; [[ $? = 2 ]] && return 2
	echo ; echo "Performing ACK scan on port 53..." ; sudo nmap -sA -Pn -n --disable-arp-ping -p 53 $ip --packet-trace --source-port 80 >> autoscan && Rcheck ; [[ $? = 2 ]] && 53Udp
	echo ; echo "Performing SYN scan on port 53..." ; sudo nmap -sS -Pn -n --disable-arp-ping -p 53 $ip --packet-trace --source-port 443 >> autoscan && opencheck ; [[ $? = 2 ]] && return 2
	echo ; echo "Performing ACK scan on port 53..." ; sudo nmap -sA -Pn -n --disable-arp-ping -p 53 $ip --packet-trace --source-port 443 >> autoscan && Rcheck ; [[ $? = 2 ]] && 53Udp
	echo ; echo "Giving UDP scan a go anyway..." ; 53Udp
}



function 53Udp() {
	###Performs datagram scan on port 53/udp, looking for an open state. If open, performs intense version scan with script-trace in order to capture as much data as possible; looks for version number.
	###Performs this sequence with source port 80 and 443 
	echo ; echo -e "${txtred}~~~~~~~~~~Beginning sU scan on UDP port 53!~~~~~~~~~~${txtrst}"
	sudo nmap -sU -p 53 -Pn -n --disable-arp-ping $ip --source-port 80 --packet-trace >> autoscan && cat autoscan | grep -w open -A 100 && opencheck
	if [[ $? = 2 ]]; then sudo nmap -sUV -p 53 -Pn -n --version-intensity 9 --disable-arp-ping $ip --script-trace --source-port 80 >> sUV | cat sUV | grep -w report -A 100 ; fi && return 2
	sudo nmap -sU -p 53 -Pn -n --disable-arp-ping $ip --source-port 443 --packet-trace >> autoscan && cat autoscan | grep -w open -A 100 && opencheck
	if [[ $? = 2 ]]; then sudo nmap -sUV -p 53 -Pn -n --version-intensity 9 --disable-arp-ping $ip --script-trace --source-port 443 >> sUV | cat sUV | grep -w report -A 100 ; fi && return 2
}



function filteredscan() {
	ackscan ; [[ $? = 2 ]] && sourcedns ; [[ $? = 2 ]] && return 2
}



function sourcedns() {
	sudo nmap -sS --source-port 53 -Pn -n --disable-arp-ping -p $port $ip --packet-trace >> autoscan && opencheck
}



function checkICMP() {
	[[ $ICMP =~ ^[I][C][M][P]$ ]] 
}



function httpenum() {
	 sudo nmap --script vuln -p $port $ip --reason >> Vuln_Scan_HTTP && cat Vuln_Scan_HTTP | grep -w PORT -A 50
}



function httpenum_source() {
	 sudo nmap --source-port 53 --script vuln -p $port $ip --reason >> Vuln_Scan_HTTP && cat Vuln_Scan_HTTP | grep -w PORT -A 50
}



function scanprogress() {
	pid=$! 
	trap "kill $pid 2> /dev/null" EXIT
	while kill -0 $pid 2> /dev/null ; do percent=$(tail -n 1 allportscan | grep -w About | cut -d':' -f2 | cut -d' ' -f3) ; printf "\r%s" "$percent" ; sleep 1 ; done
	[[ $? = 0 ]] && echo -en "\033[2k" && printf "\r%s" "100%"
	trap - EXIT
}



function scanprogressVersion() {
	pid=$! 
	trap "kill $pid 2> /dev/null" EXIT
	while kill -0 $pid 2> /dev/null ; do percent=$(tail -n 1 nmapScan_sV_openports | grep -w About | cut -d':' -f2 | cut -d' ' -f3) ; printf "\r%s" "$percent" ; sleep 1 ; done
	[[ $? = 0 ]] && echo -en "\033[2k" && printf "\r%s" "100%"
	trap - EXIT
}



function beginvuln() {
	echo ; echo 
	echo -e "${txtred}~~~~~~~~~~Beginning vulnerability script scan on HTTP ports!~~~~~~~~~~${txtrst}"
}



echo 
echo -e "${txtred}~~~~~~~~~~Beginning default Script scan on ALL ports!~~~~~~~~~~${txtrst}"
sudo nmap -sC -n -Pn --disable-arp-ping --min-rate 100 --stats-every 1s $ip >> allportscan & scanprogress && echo && cat allportscan | grep -w PORT -A 100
filteredports=$(cat allportscan | grep -w "filtered" | grep ^[0-9] | cut -d'/' -f1 | tr '\n' ',' | sed s/,$//)



echo ; echo 
echo -e "${txtyel}~~~~~~~~~~Beginning Version scan on all OPEN ports!~~~~~~~~~~${txtrst}"
openports=$(cat allportscan | grep -w "open" | grep ^[0-9] | cut -d'/' -f1 | tr '\n' ',' | sed s/,$//) ; [[ -n $openports ]] && sudo nmap -sV --version-intensity 9 -Pn -n $ip -p $openports --reason --stats-every 1s >> nmapScan_sV_openports & scanprogressVersion && echo
[[ -n $openports ]] && cat nmapScan_sV_openports | grep -w PORT -A 100 || echo "No open ports found."



port53=$(cat allportscan | grep -w "filtered" | grep -w "53" | grep ^[0-9] | cut -d'/' -f1 | tr '\n' ',' | sed s/,$//) ; [[ -n $port53 ]] && echo && echo && echo -e "${txtgreen}~~~~~~~~~~Beginning enumeration scans on DNS port!~~~~~~~~~~${txtrst}" && dns44380



HTTP=$(cat allportscan | grep -w "filtered" | grep -w "http" | grep ^[0-9] | cut -d'/' -f1 | tr '\n' ',' | sed s/,$//) ; [[ -n $HTTP ]] && port=$HTTP && filteredscan && [[ $? = 2 ]] && beginvuln && httpenum_source 
HTTP=$(cat allportscan | grep -w "http" | cut -d" " -f1-6 | grep -w "open" | cut -d"/" -f1) ; [[ -n $HTTP ]] && beginvuln && port=$HTTP && httpenum



[[ -z $openports ]] && [[ -z $filteredports ]] && echo && echo\
&& echo -e "${txtblue}~~~~~~~~~~No Filtered or Open ports~~~~~~~~~~${txtrst}"\
&& cat allportscan



echo ; rm filteredports openports autoscan sUV 2> /dev/null ; exit



###EVERYTHING BELOW THIS POINT ARE IDEAS I'VE WRITTEN IN ORDER TO IMPLAMENT IN THE FUTURE



#-sU responce from ICMP of (type=3/code=3) means UDP port is CLOSED



#sT does NOT work with source port
#xsltproc Scan.xml -o Scan.html

#if multiple hosts, and more than 1 are up, compare IPs to find network address 
#	-try option	-S using matching network IP with host octet that my be within subnet
#option:	-v will show 'Discovered open port ' followed by 'number/tcp or udp on IP'
#Option	-A scan should show host name that appears on a line that looks like below
#	Service Info: Host: NIX-NMAP-DEFAULT

#xsltproc target.xml -o target.html 
#us greppable file instead of touching???


#$ICMP = $'\0'
#$unreachable = $'\0'
#       	[[ ! $ICMP =~ ^[I][C][M][P]$ ]]
 #      	&& echo "No match to ICMP"

#if ICMP and (type=3/code=3) <----this is correct syntax and host UP and scan time < t and state is filtered and reason no response 
#then
#	echo "Good chance firewall is protecting this port NOTE FOR LATER!!!!"

#	-A with -v	will give more verbose out put inlcuding DNS resolution Name if found

#[[ ! $unreachable =~ ^[u][n][r][e][a][c][h][a][b][l][e]$ ]] && echo "No match to unreachable"
#!/bin/bash

#        E. NFS(NETWORK FILE SYSTEM
#                1.) Primarily used with Linux/Unix
#                2.) Enumerate with nmap:
#                        -       sudo nmap -sV -sC -p ports IP
#                        -       sudo nmap -sV --script nfs* IP -p ports

#    6. Consider following scripts:
#                        -SMB_BF.sh      location: EnumScripts in Mainbox
#                        -samrdump.py    location: /usr/share/doc/python3-impacket/examples/samrdump.py in Mainbox
#                7. Other Enumeration Tools for SMB
#                        -smbmap
#                                .syntax:        smbmap -u Username -p PASSWORD -H [IP]
#                                .syntax:        smbmap -u guest -H [IP]
#                        -CrackMapExec
#                                .syntax         crackmapexec smb [IP]
#                        -enum4linux-ng
#
#IMAP and IPOP ports suseptible to sV and sC; may give information such as capabilities and domain name with email
#
#
