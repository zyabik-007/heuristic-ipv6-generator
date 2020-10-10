# The necessary programs
    
  - ```nmap``` 
  
  - Python 3
  
  - Internet access through IPV6 for scanning

# PIP dependings

- shutil
- datetime
- os
- ipaddress
- argparse
- dns.resolver

 # How to start

    python main.py
    
Command example: 
 
 `python main.py -wordAddresses -servicePort -lowbyte -ipv4InIpv6 -macInIpv6 -parseDomain -ports 80,21,22,443 -clearOutput -clearOutputNmap -countToWrite 100 -limitGenerate 100 -executeNmap 0 -nmapScan out`


# Command List

- `-h --help`     Show this help message and exit
- `-wordAddresses` Use method wordAddresses to generate
- `-macInIpv6` Use method macInIpv6 to generate
- `-servicePort` Use method servicePort to generate
- `-lowbyte` Use method lowbyte to generate
- `-ipv4InIpv6` Use method ipv4InIpv6 to generate
- `-generateMacAddresses` Generate a list of mac addresses
- `-parseDomain` Parse IPv6 list from domain list data/domains.txt
- `-ports 80,443` list of ports that will be used in the scanner
- `-clearOutput` Сlear output directory
- `-clearOutputNmap` Сlear output nmap directory
- `-countToWrite` Buffer addresses for writing, default 1000
- `-nmapScan <diectory>` example `-nmapScan out` Nmap custom scan all files in directory, default <directory> : out 
- `-executeNmap 1` -executeNmap 0|1 scan ipv6 addresses after generate? 0 - no, 1 - yes, default 0
- `-limitGenerate` Limit of generate IPv6 addresses
  
  
# Description

The script generates IPV6 addresses according to frequently used patterns, which allow generating IPV6 speakers into which active hosts will be with a higher percentage

Generation Templates:
- Word Adresses
- mac in IPV6
- Service Port
- Low byte
- Ipv4 In Ipv6
       
A file with IPV6 addresses is generated which is then passed to nmap

Used fragmentation for recording so as not to overflow memory with very large generation spaces

