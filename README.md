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

 
# Command List

  - h, --help     show this help message and exit
  - wordAdresses,  Generate wordAdresses template
  - macInIpv6,     Generate macInIpv6 template
  - servicePort,   Generate servicePort template
  - lowbyte,       Generate lowbyte template
  - ipv4InIpv6,    Generate ipv4InIpv6 template
  - parseDomain,   Generate domain template
  - ports,   List of ports 80,443
  - geneareMacAdresses, Generate domain template
  - clearOutput,       Clear output directory
  - clearOutputNmap,   Clear output nmap directory

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

# How to start
    python main.py  
    

