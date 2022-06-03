# Automate Hunting for Behinder Webshell with yara
---

## Install YARA on webserver
- install yara-scanner
` sudo pip install yara-scanner`

-verify yara scanner install

`scan -h`

- Make directory to place you behinder yara rule

`sudo mkdir -p /opt/signatures/webshells`

- Get yara rule released by volexity
```
sudo wget https://raw.githubusercontent.com/volexity/threat-intel/main/2022/2022-06-02%20Active%20Exploitation%20Of%20Confluence%200-day/indicators/yara.yar -O /opt/signatures/webshells/behinder.yar
```
- make Directory to store Yara Matches

` sudo mkdir -p /opt/yara_matches`

- Test Shell script to scan your directory of web service

```
sudo su -
```
- paste all that follows as one command
```
LOGDATE=$(date +%Y%m%dT%H%M%S)
/usr/local/bin/scan -j -r /YourIntendedScan/Path/ | jq '.' > /opt/yara_matches/"$LOGDATE".json
```

- Verify command works
  - After command has finished check /opt/yara_matches for logs
```
ls -l /opt/yara_matches/
```

- Make script to run for cron

```
cd /root
nano yara_log.sh
```

- Paste the script into the yara_log.sh within nano and then save by hitting control X and then Y

```
#! /bin/bash
LOGDATE=$(date +%Y%m%dT%H%M%S)                                                                                            
/usr/local/bin/scan -j -r /home/kali/ | jq '.' > /opt/yara_matches/"$LOGDATE".json
```

- Make script executable for root only. 
- Ensure that it is not world writeable.  permissions should be 744

```
chmod u+x yara_log.sh
chmod 744 yara_log.sh
```
- Make cron job
  - Ensure you give sufficient interval for the cron job to finish if scanning directories with large amounts of files. Pay attention to how long it took for the test to finish and base interval off that. 

```
crontab -e
```


## CREDIT/References
- Volexity
https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/

https://github.com/volexity/threat-intel/blob/main/2022/2022-06-02%20Active%20Exploitation%20Of%20Confluence%200-day/indicators/yara.yar

- Yara-Scanner resources

- Mark Ernest
  - This guide heavily borrows from his blog article. His article is tailored towards a lab environment but works nicely for this purpose as well.  Note I did switch a few minor things such as the yara rule and use of jq instead of json_pp

https://markernest.medium.com/web-shells-yara-log-collection-automation-with-hands-on-lab-bd8240d20aee

- yara-scanner install 
https://pypi.org/project/yara-scanner/