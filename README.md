There's an issue that resides within the functions 'scanprogress' and 'scanprogressVersion'.
I recieve an error 'Segmentation Fault' on the line of code where the function is created.
This occurs anytime I run the script where the while loop condition within the 
function becomes false. At least that's what it looks like to me.
I believe this has something to do with the older version 7.92; newer is 7.93

Scan simply sources port 80 and 443 in an attempt to get filtered ports open.
I plan on adding the ability to automatically determine whether firewall is statefull/stateless.
I also plan on adding various nmap features like fragmentation, decoys, and others; I need to get
data on what succeeds in the wild.
I'd also like to add a way to change scan intensity before starting.
