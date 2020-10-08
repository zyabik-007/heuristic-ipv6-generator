import shutil
import threading
from datetime import datetime
import os
import ipaddress
import argparse
import dns.resolver

COUNT_TO_WRITE = 1000

OUT_NMAP_DIRECTORY = "outNmap/"
OUT_DIRECTORY = "out/"
DATA_DIRECTORY = "data/"

FILE_PREFIX_LIST = DATA_DIRECTORY + "ipv6-prefix.txt"
FILE_PREFIX_LIST = OUT_DIRECTORY + "addressesFromDomain.txt"
FILE_HEX_WORD = DATA_DIRECTORY + "hex-word.txt"
FILE_MAC_PREFIX = DATA_DIRECTORY + "mac-prefix.txt"
FILE_DOMAINS = DATA_DIRECTORY + "domains.txt"


def generateSequenceAddresses(prefix, length, fileNameOut):
    log("stat generateSequenceAddresses, prefix:" + str(prefix))
    length += 1
    out = []
    i = 0
    ip = getIp(prefix)
    for a in range(length):
        i += 1
        if (a > COUNT_TO_WRITE):
            writeToFile(out, fileNameOut)
            out = []
            i = 0
        out.append(ip + a)
    writeToFile(out, fileNameOut)
    log("end generateSequenceAddresses, prefix:" + str(prefix))


def writeToFile(addresses, file):
    if os.path.exists(file):
        f = open(file, 'a')
    else:
        f = open(file, 'w')

    for ip in addresses:
        try:
            f.write(ipaddress.IPv6Interface(ip).network.network_address.compressed + '\n')
        except NameError:
            print("Error IPV6 compressed " + NameError)
    f.close()


def writeToFileItems(items, file):
    if os.path.exists(file):
        f = open(file, 'a')
    else:
        f = open(file, 'w')

    for item in items:
        try:
            f.write(item + '\n')
        except NameError:
            print("Error write " + NameError)
    f.close()


def remove_duplicates(raw_file):
    addrs = raw_file.readlines()
    for i in range(len(addrs)):
        addrs[i] = ipaddress.IPv6Interface(addrs[i][:-1])
    uniques = set(addrs)
    return uniques


def readPrefixes(fileName):
    f = open(fileName)
    prefixes = f.readlines()
    f.close()
    for i in range(len(prefixes)):
        prefixes[i] = ipaddress.IPv6Interface(prefixes[i][:-1])
    return set(prefixes)


def generateIpv4InIpv6(prefix, aLim=255, bLim=255, cLim=255, dLim=255, fileNameOut=""):
    log("stat generateIpv4InIpv6, prefix:" + str(prefix))
    aLim += 1
    bLim += 1
    cLim += 1
    dLim += 1
    out = []
    i = 0
    ip = getIp(prefix).exploded.split(":")
    ip.pop(7)
    ip.pop(6)
    ip.pop(5)
    ip.pop(4)
    ip = ":".join(ip)
    for a in range(aLim):
        for b in range(bLim):
            for c in range(cLim):
                for d in range(dLim):
                    i += 1
                    out.append(str(ip) + ":" + str(a) + ":" + str(b) + ":" + str(c) + ":" + str(d))
                    if (i > COUNT_TO_WRITE):
                        writeToFile(out, fileNameOut)
                        out = []
                        i = 0
    writeToFile(out, fileNameOut)
    log("end generateIpv4InIpv6, prefix:" + str(prefix))


def generateLowbyte(prefix, fileNameOut):
    log("stat generateLowbyte, prefix:" + str(prefix))
    generateSequenceAddresses(prefix, 255, fileNameOut)
    log("end generateLowbyte, prefix:" + str(prefix))


def generateServicePort(prefix, fileNameOut):
    log("stat generateServicePort, prefix:" + str(prefix))
    out = []
    ports = [20, 21, 22, 23, 25, 53, 80, 8080, 110, 119, 123, 135, 139, 143, 161, 194, 443, 445, 993, 995, 1723, 3306,
             5900, 3389]
    ip = getIp(prefix)
    for port in ports:
        out.append(ip + port)
    writeToFile(out, fileNameOut)
    log("end generateServicePort, prefix:" + str(prefix))


def mac2eui64(mac, prefix=None):
    mac_parts = mac.split(":")
    pfx_parts = getIp(prefix).exploded.split(":")
    eui64 = mac_parts[:3] + ["ff", "fe"] + mac_parts[3:]
    eui64[0] = "%02x" % (int(eui64[0], 16) ^ 0x02)
    ip = ":".join(pfx_parts[:4])
    for l in range(0, len(eui64), 2):
        ip += ":%s" % "".join(eui64[l:l + 2])
    return ip


def executeNmapPath(entryFileNameIn, pathDirOut, ports):
    command = "nmap -p " + ','.join(
        [str(i) for i in
         ports]) + " -6 -iL " + entryFileNameIn.path + " -oN " + pathDirOut + "/" + entryFileNameIn.name + " --stats-every 60s"
    log(command)
    print(command)
    os.system(command)


def executeNmap(fileNameIn, ports):
    if args.executeNmap != None:
        if args.executeNmap[0] == '1':
            # if not os.path.exists(OUT_NMAP_DIRECTORY):
            #     os.makedirs(OUT_NMAP_DIRECTORY)

            output = OUT_NMAP_DIRECTORY + "output_" + fileNameIn.split("/")[-1] + "_.txt"
            command = "nmap -p " + ','.join([str(i) for i in ports]) + " -6 -iL " + fileNameIn + " -oN " + output
            log(command)
            os.system(command)


def getDateTime():
    now = datetime.now()
    return now.strftime("%d-%m-%Y_%H_%M_%S")


def generateWordAdresses(prefix, fileNameIn, fileNameOut):
    log("stat generateWordAdresses, prefix:" + str(prefix))
    f = open(fileNameIn)
    words = f.read().splitlines()
    ip = getIp(prefix).exploded
    ipParts = ip.split(":")
    ipParts.pop(7)
    ipParts.pop(6)
    prefix = ":".join(ipParts)
    out = []
    i = 0
    for word1 in words:
        for word2 in words:
            if (i > COUNT_TO_WRITE):
                writeToFile(out, fileNameOut)
                out = []
                i = 0
            out.append(prefix + ":" + word1 + ":" + word2)
    writeToFile(out, fileNameOut)
    f.close()
    log("end generateWordAdresses, prefix:" + str(prefix))


def log(text, file=0):
    if file == 0:
        file = "logs.log"
    file = "logs/" + file
    if os.path.exists(file):
        f = open(file, 'a')
    else:
        f = open(file, 'w')
    f.write(getDateTime() + " " + text + "\n")
    f.close()


def geneareMac(prefix, fileNameOut):
    out = []
    i = 0
    for number in range(16 ** 6):
        i += 1
        hex_num = hex(number)[2:].zfill(6)
        if (i > COUNT_TO_WRITE):
            writeToFileItems(out, fileNameOut)
            out = []
            i = 0
        out.append("{}:{}{}:{}{}:{}{}".format(prefix, *hex_num))
    writeToFileItems(out, fileNameOut)


def geneareMacAdresses():
    log("start geneareMacAdresses")
    f = open(FILE_MAC_PREFIX)
    line = f.readline().rstrip('\n')
    while line:
        mac = f.readline().rstrip('\n')
        geneareMac(mac, DATA_DIRECTORY + "mac.txt")
    f.close()
    log("end geneareMacAdresses")


def getIp(prefix):
    return ipaddress.IPv6Interface(prefix).network.network_address


def generateMacInIpv6(prefix, fileNameIn, fileNameOut):
    log("stat generateMacInIpv6, prefix:" + str(prefix))
    f = open(fileNameIn)
    line = f.readline().rstrip('\n')
    out = []
    i = 0
    prefix = getIp(prefix)
    while line:
        i += 1
        if (i > COUNT_TO_WRITE):
            writeToFile(out, fileNameOut)
            out = []
            i = 0
        mac = f.readline().rstrip('\n')
        out.append(mac2eui64(mac=mac, prefix=prefix))
    f.close()
    writeToFile(out, fileNameOut)
    log("end generateMacInIpv6, prefix:" + str(prefix))


global flag
flag = False
global threads
threads = []


def getAAAARecord(domain):
    try:
        result = dns.resolver.query(domain, 'AAAA')
        if result[0]:
            while True:
                if flag == False:
                    outDomains.append(result[0].address)
                    break
    except:
        return None
    return None


def parseDomain(fileNameIn, fileNameOut):
    global outDomains
    outDomains = []
    log("stat generateParseDomain")
    f = open(fileNameIn)
    domain = f.readline().rstrip('\n')
    i = 0
    progress = 0
    while domain:
        if (len(threads) <= 1000):
            i += 1
            if progress % 1000 == 0:
                print('progress=' + str(progress))
            if (len(outDomains) > COUNT_TO_WRITE):
                print('writeToFile')
                flag = True
                writeToFile(outDomains, fileNameOut)
                outDomains = []
                flag = False
                i = 0
            x = threading.Thread(target=getAAAARecord, args=(domain,))
            x.start()
            progress += 1
            threads.append(x)
            domain = f.readline().rstrip('\n')
            for idx, val in enumerate(threads):
                if val.isAlive() == False:
                    threads.pop(idx)

    f.close()
    writeToFile(outDomains, fileNameOut)
    for th in threads:
        th.join()
    log("end generateParseDomain")


def clear(dir):
    with os.scandir(dir) as entries:
        for entry in entries:
            if entry.is_file() or entry.is_symlink():
                if entry.name != '.gitignore':
                    os.remove(entry.path)
            elif entry.is_dir():
                shutil.rmtree(entry.path)


parser = argparse.ArgumentParser(description='Command List')

parser.add_argument('-wordAdresses', nargs='*', help="Generate wordAdresses template")
parser.add_argument("-macInIpv6", nargs='*', help="Generate macInIpv6 template")
parser.add_argument("-servicePort", nargs='*', help="Generate servicePort template")
parser.add_argument("-lowbyte", nargs='*', help="Generate lowbyte template")
parser.add_argument("-ipv4InIpv6", nargs='*', help="Generate ipv4InIpv6 template")
parser.add_argument("-parseDomain", nargs='*', help="Generate domain template")
parser.add_argument("-ports", nargs='?', help="List of ports 80,443")
parser.add_argument("-geneareMacAdresses", nargs='*', help="Generate domain template")
parser.add_argument("-clearOutput", nargs='*', help="clear output directory")
parser.add_argument("-clearOutputNmap", nargs='*', help="clear output nmap directory")
parser.add_argument("-countToWrite", nargs='*', help="count buffer line to write to file")
parser.add_argument("-nmapScan", nargs='*', help="-nmapScan <directory>   Nmap custom scan all files in directory ")
parser.add_argument("-executeNmap", nargs='*',
                    help="-executeNmap 0|1 scan ipv6 adress after generate? 0 - no, 1 - yes, default 0")

# -clearOutput -clearOutputNmap -ports 80,443 -wordAdresses -macInIpv6 -servicePort -lowbyte -ipv4InIpv6 -parseDomain -geneareMacAdresses
# -wordAdresses -servicePort -lowbyte -ipv4InIpv6
# -wordAdresses -servicePort -lowbyte -ipv4InIpv6
# grep -o "80/tcp open     http" outNmap.txt  | wc -l

args = parser.parse_args()
log("start program")
ports = [80]
if args.ports != None:
    ports = args.ports.split(",")

if args.nmapScan != None:
    nmapDirectoryIn = args.nmapScan[0]
    entries = os.scandir(nmapDirectoryIn)
    for entry in entries:
        if entry.name != ".gitignore":
            executeNmapPath(entry, OUT_NMAP_DIRECTORY, ports)

if args.countToWrite != None:
    COUNT_TO_WRITE = int(args.countToWrite[0])

if args.clearOutput != None:
    clear(OUT_DIRECTORY)

if args.clearOutputNmap != None:
    clear(OUT_NMAP_DIRECTORY)

if args.geneareMacAdresses != None:
    geneareMacAdresses()

if args.parseDomain != None:
    parseDomain(FILE_DOMAINS, OUT_DIRECTORY + "addressesFromDomain.txt")
prefixes = readPrefixes(FILE_PREFIX_LIST)
for prefix in prefixes:
    global dateDime
    # dateDime = (str(prefix).translate({ord(':'): None, ord('/'): None})) + "__" + getDateTime()
    dateDime = ''
    # os.mkdir(OUT_DIRECTORY + dateDime)
    # os.mkdir(OUT_NMAP_DIRECTORY + dateDime)
    # dateDime = dateDime + "/"
    if args.wordAdresses != None:
        generateWordAdresses(prefix, FILE_HEX_WORD, OUT_DIRECTORY + dateDime + "WordAdresses.txt")
        executeNmap(OUT_DIRECTORY + dateDime + "WordAdresses.txt", ports)

    if args.macInIpv6 != None:
        generateMacInIpv6(prefix, DATA_DIRECTORY + dateDime + "mac.txt", OUT_DIRECTORY + dateDime + "MacInIpv6.txt")
        executeNmap(OUT_DIRECTORY + dateDime + "MacInIpv6.txt", ports)

    if args.servicePort != None:
        generateServicePort(prefix, OUT_DIRECTORY + dateDime + "ServicePort.txt")
        executeNmap(OUT_DIRECTORY + dateDime + "ServicePort.txt", ports)

    if args.lowbyte != None:
        generateLowbyte(prefix, OUT_DIRECTORY + dateDime + "Lowbyte.txt")
        executeNmap(OUT_DIRECTORY + dateDime + "Lowbyte.txt", ports)

    if args.ipv4InIpv6 != None:
        generateIpv4InIpv6(prefix, 255, 255, 255, 255, OUT_DIRECTORY + dateDime + "Ipv4InIpv6.txt")
        executeNmap(OUT_DIRECTORY + dateDime + "Ipv4InIpv6.txt", ports)
