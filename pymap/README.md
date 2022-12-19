pymap does what testmap does, except it also does a basic check for target firewall statefullness by comparing already determined open ports to others
not yet checked. A list of 100 ports, including those found open, are scanned with SYN packets, then ACK packets. Those that respond with RST from ACK
are determined to be NON-stateful. While those that don't respond, but were originally found OPEN, are determined to be stateful. 

pymap does NOT use the default script option as I found it difficult to parse this data with python. Still learning.

I made this as a process to learn firewall rule sets mentioned at https://nmap.org/book/determining-firewall-rules.html.

Works with python3.10.8. Using native libraries. I think you might have to pip install colorama. 
