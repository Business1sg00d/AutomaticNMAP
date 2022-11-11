#!/bin/bash
###GOAL: Automatically seek open ports by performing sequence of scans to bypass firewall
###At the end of scan; list open ports with their services
###Give user the option to perform enumeration scans/vuln scans
###Allport scan
###Perform service scans on open ports
###Perform filterscans to find open port through sourcedns



#Text Colors
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
#Rst Color    0m



#using sudo in order to use subsequent scans under root privileges
sudo clear
echo "Enter IP" ; read ip ; clear


#Source ports 80 and 443 in order to get 53/tcp open. Echos if successfull. Moves on to 53/udp port scan using the same methods.
function dns44380() {
	s=0
	while true; do ((s++)); [ "$s" -gt "2" ] && break; [[ $s = [1] ]] && source='--source-port 80'; [[ $s = [2] ]] && source='--source-port 443';\
		openports=$(sudo nmap -sS -Pn -n --disable-arp-ping -p 53 ${source} ${ip} | grep -w "open");
		[[ -n $openports ]] && echo -e "${txtred}~~~~~~~~~~Port 53/tcp ${txtgreen}OPEN${txtred} with $source and SYN flag!${txtrst}~~~~~~~~~~"\
		&& echo && break && return 2; done; 53Udp
}



function 53Udp() {
	s=0
	while true; do ((s++)); [ "$s" -gt "2" ] && break; [[ $s = [1] ]] && source='--source-port 80'; [[ $s = [2] ]] && source='source-port 443';\
		openports=$(sudo nmap -sU -p 53 -Pn -n --disable-arp-ping ${ip} ${source} | grep -w "open");
		[[ -n $openports ]] && echo -e\
		"${txtblue}~~~~~~~~~~Port 53/udp ${txtgreen}OPEN${txtblue} with $source! Now doing sUV scan~~~~~~~~~~${txtrst}" && echo\
		&& sudo nmap -sUV -p 53 -Pn -n --version-intensity 9 --script-trace --disable-arp-ping ${ip} ${source} >> sUVscan && cat sUVscan\
		| grep -w "open" -A 100 && break && return 2; done
}


#If filtered ports are returned from all port scan, attempts to determine if they might be active via ACK scan *NOTE* determine if stateful/stateless 1st
#If port returns as unfiltered(RST packet recieved), then goes onto source port 53 with SYN scan on filtered ports. Echos if successfull.
function filteredscan() {
	unfilteredarray=()
	filteredarray=()
	unfilteredports=$(sudo nmap -sA -Pn -n --disable-arp-ping -p $1 $ip | grep -w "unfiltered" | grep ^[0-9] | cut -d'/' -f1)

	if [[ -n $unfilteredports ]]; then
		for port in "${unfilteredports}"; do [[ ! ${unfilteredarray[*]} =~ $port ]] && unfilteredarray+=("$port"); done
		newports=$(echo ${unfilteredarray[@]} | tr ' ' ',')
		openports=$(sudo nmap -sS --source-port 53 -Pn -n --disable-arp-ping -p $newports $ip | grep -w "open" | grep ^[0-9] | cut -d'/' -f1)

		if [[ -n $openports ]]; then
			openportA=()
			addtofiltered=$(echo ${unfilteredarray[@]} ${openportA[@]} | tr ' ' '\n' | sort | uniq -u)
			for port in "${openports}"; do [[ ! ${openportA[*]} =~ $port ]] && openportA+=("$port"); done
			for port in "${addtofiltered}"; do filteredarray+=("$port"); done
			listports=$(echo ${openportA[@]} | tr ' ' ',')
			echo -e "${txtred}~~~~~~~~~~Found ports'${listports}'${txtgreen}OPEN${txtred} with --source-port 53 option for nmap.\
			~~~~~~~~~~${txtrst}" && echo
			return 2
		else
			for port in "${unfilteredports}"; do filteredarray+=("$port"); done
		fi	
	fi
}



function httpenum() {
	 sudo nmap --script vuln -p $1 $ip --reason >> Vuln_Scan_HTTP ; cat Vuln_Scan_HTTP | grep -w PORT -A 50
}



function httpenum_source() {
	 sudo nmap --source-port 53 --script vuln -p $1 $ip --reason >> Vuln_Scan_HTTP ; cat Vuln_Scan_HTTP | grep -w PORT -A 50
}



function scanprogress() {
	pid=$! 
	trap "kill $pid 2> /dev/null" EXIT
	while kill -0 $pid 2> /dev/null ; do percent=$(tail -n 1 allportscan | grep -w About | cut -d':' -f2 | cut -d' ' -f3)\
	; printf "\r%s" "$percent" ; sleep 1 ; done
	[[ $? = 0 ]] && echo -en "\033[2k" && printf "\r%s" "100%"
	trap - EXIT
}



function scanprogressVersion() {
	pid=$! 
	trap "kill $pid 2> /dev/null" EXIT
	while kill -0 $pid 2> /dev/null ; do percent=$(tail -n 1 nmapScan_sV_openports | grep -w About | cut -d':' -f2 | cut -d' ' -f3)\
	; printf "\r%s" "$percent" ; sleep 1 ; done
	[[ $? = 0 ]] && echo -en "\033[2k" && printf "\r%s" "100%"
	trap - EXIT
}



function beginvuln() {
	echo ; echo 
	echo -e "${txtred}~~~~~~~~~~Beginning vulnerability script scan on HTTP ports!~~~~~~~~~~${txtrst}"
}



echo 
echo -e "${txtred}~~~~~~~~~~Beginning default Script scan on ALL ports!~~~~~~~~~~${txtrst}"
sudo nmap -sC -n -Pn --disable-arp-ping --min-rate 100 --stats-every 1s -p- $ip 2> /dev/null >> allportscan & scanprogress && echo\
&& cat allportscan | grep -w PORT -A 100
filteredports=$(cat allportscan | grep -w "filtered" | grep ^[0-9] | cut -d'/' -f1 | tr '\n' ',' | sed s/,$//)



echo ; echo 
echo -e "${txtyel}~~~~~~~~~~Beginning Version scan on all OPEN ports!~~~~~~~~~~${txtrst}"
openports=$(cat allportscan | grep -w "open" | grep ^[0-9] | cut -d'/' -f1 | tr '\n' ',' | sed s/,$//)
[[ -n $openports ]] && touch nmapScan_sV_openports && sudo nmap -sV --version-intensity 9 -Pn -n $ip -p $openports --reason --stats-every 1s 2> /dev/null\
>> nmapScan_sV_openports & scanprogressVersion && echo
[[ -n $openports ]] && cat nmapScan_sV_openports | grep -w PORT -A 100 || echo "No open ports found."



port53=$(cat allportscan | grep -w "filtered" | grep -w "53" | grep ^[0-9] | cut -d'/' -f1 | tr '\n' ',' | sed s/,$//)
[[ -n $port53 ]] && echo && echo && echo -e "${txtgreen}~~~~~~~~~~Beginning enumeration scans on DNS port!~~~~~~~~~~${txtrst}" && dns44380



HTTPfiltered=$(cat nmapScan_sV_openports | grep -w "filtered" | grep -w "http" | grep ^[0-9] | cut -d'/' -f1 | tr '\n' ',' | sed s/,$//) 
[[ -n $HTTPfiltered ]] && filteredscan "$HTTPfiltered" && [[ $? = 2 ]] && beginvuln && httpenum_source "$HTTPfiltered"
HTTP=$(cat nmapScan_sV_openports | grep -w "open" | grep -w "http" | grep ^[0-9] | cut -d"/" -f1 | tr '\n' ',' | sed s/,$//)
[[ -n $HTTP ]] && beginvuln && httpenum "$HTTP"



#exclude port 53 and/or HTTP ports because the above already checks and enumerates their filtered states.
filteredports=$(cat nmapScan_sV_openports | grep -w "filtered" | grep ^[0-9] | grep -v "53" | grep -v "http" | cut -d'/' -f1 | tr '\n' ',' | sed s/,$//)
[[ -n $filteredports ]] && filteredscan "$filteredports"



[[ -z $openports ]] && [[ -z $filteredports ]] && echo && echo\
&& echo -e "${txtblue}~~~~~~~~~~No Filtered or Open ports~~~~~~~~~~${txtrst}"\
&& cat allportscan | grep -w Host -A 5 



exit
