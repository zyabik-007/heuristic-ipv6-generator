import shutil
import threading
from datetime import datetime
import os
import ipaddress
import argparse
import dns.resolver

COUNT_TO_WRITE = 1000
LIMIT_GENERATION = float('inf')

OUT_NMAP_DIRECTORY = "outNmap/"
OUT_DIRECTORY = "out/"
DATA_DIRECTORY = "data/"

FILE_PREFIX_LIST = DATA_DIRECTORY + "domains_alexa_topIPV6_zakres_1.txt"
FILE_PREFIX_LIST = DATA_DIRECTORY + "domains_alexa_topIPV6_zakres_2.txt"

FILE_PREFIX_LIST = DATA_DIRECTORY + "top_10_mln_domainsIPV6_zakres_1.txt"
FILE_PREFIX_LIST = DATA_DIRECTORY + "top_10_mln_domainsIPV6_zakres_2.txt"

FILE_HEX_WORD = DATA_DIRECTORY + "hex-word.txt"
FILE_MAC_PREFIX = DATA_DIRECTORY + "mac-prefix.txt"
FILE_DOMAINS = DATA_DIRECTORY + "domains_alexa_top.txt"
FILE_DOMAINS = DATA_DIRECTORY + "top_10_mln_domains.txt"

global allCount
global prefixes
global threads
threads = []


def generateSequenceAddresses(prefix, length, fileNameOut):
    global allCount
    log("stat generateSequenceAddresses, prefix:" + str(prefix))
    length += 1
    out = []
    progress = 0
    ip = getIp(prefix)
    for a in range(length):
        if (progress > COUNT_TO_WRITE):
            writeToFile(out, fileNameOut)
            out = []
            if allCount >= LIMIT_GENERATION:
                break
            progress = 0
        out.append(ip + a)
        progress = progress + 1
        allCount += 1
        if allCount >= LIMIT_GENERATION:
            break
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
        if len(prefixes[i]) >= 2:
            prefixes[i] = ipaddress.IPv6Interface(prefixes[i][:-1])
    return set(prefixes)


def generateIpv4InIpv6(prefix, aLim=255, bLim=255, cLim=255, dLim=255, fileNameOut=""):
    global allCount
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
    flagBreak = False
    for a in range(aLim):
        for b in range(bLim):
            for c in range(cLim):
                for d in range(dLim):
                    i += 1
                    out.append(str(ip) + ":" + str(a) + ":" + str(b) + ":" + str(c) + ":" + str(d))
                    if (i > COUNT_TO_WRITE):
                        writeToFile(out, fileNameOut)
                        out = []
                        allCount += i
                        if allCount >= LIMIT_GENERATION:
                            flagBreak = True
                            break
                        i = 0
                if flagBreak:
                    break
            if flagBreak:
                break
        if flagBreak:
            break
    writeToFile(out, fileNameOut)
    log("end generateIpv4InIpv6, prefix:" + str(prefix))


def generateLowbyte(prefix, fileNameOut):
    global allCount
    log("stat generateLowbyte, prefix:" + str(prefix))
    generateSequenceAddresses(prefix, 255, fileNameOut)
    log("end generateLowbyte, prefix:" + str(prefix))


def generateServicePort(prefix, fileNameOut):
    global allCount
    log("stat generateServicePort, prefix:" + str(prefix))
    out = []
    ports = [20, 21, 22, 23, 25, 53, 80, 8080, 110, 119, 123, 135, 139, 143, 161, 194, 443, 445, 993, 995, 1723, 3306,
             5900, 3389]
    ip = getIp(prefix)
    for port in ports:
        out.append(ip + port)
        allCount += 1
        if allCount >= LIMIT_GENERATION:
            break
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
         ports]) + " -6 -iL " + entryFileNameIn.path + " -oN " + pathDirOut + "/" + entryFileNameIn.name + " --stats-every 60s --min-parallelism 100000 -T5 -sS -PN -n"
    log(command)
    print(command)
    os.system(command)


def executeNmap(fileNameIn, ports):
    if args.executeNmap != None:
        if args.executeNmap[0] == '1':
            output = OUT_NMAP_DIRECTORY + fileNameIn.split("/")[-1]
            command = "nmap -p " + ','.join([str(i) for i in
                                             ports]) + " -6 -iL " + fileNameIn + " -oN " + output + " --stats-every 60s --min-parallelism 100000 -T5 -sS"
            log(command)
            os.system(command)


def getDateTime():
    now = datetime.now()
    return now.strftime("%d-%m-%Y_%H_%M_%S")


def generateWordAddresses(prefix, fileNameIn, fileNameOut):
    global allCount
    log("stat generateWordAddresses, prefix:" + str(prefix))
    f = open(fileNameIn)
    words = f.read().splitlines()
    ip = getIp(prefix).exploded
    ipParts = ip.split(":")
    ipParts.pop(7)
    ipParts.pop(6)
    prefix = ":".join(ipParts)
    out = []
    i = 0
    flagBreak = False
    for word1 in words:
        for word2 in words:
            if (i > COUNT_TO_WRITE):
                writeToFile(out, fileNameOut)
                out = []
                allCount = allCount + i
                if allCount >= LIMIT_GENERATION:
                    flagBreak = True
                    break
                i = 0
            out.append(prefix + ":" + word1 + ":" + word2)
            i += 1
            if flagBreak:
                break
        if flagBreak:
            break
    writeToFile(out, fileNameOut)
    f.close()
    log("end generateWordAddresses, prefix:" + str(prefix))


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


def geneareMacAddresses():
    log("start geneareMacAddresses")
    f = open(FILE_MAC_PREFIX)
    line = f.readline().rstrip('\n')
    while line:
        mac = f.readline().rstrip('\n')
        geneareMac(mac, DATA_DIRECTORY + "mac.txt")
    f.close()
    log("end geneareMacAddresses")


def getIp(prefix):
    return ipaddress.IPv6Interface(prefix).network.network_address


def generateMacInIpv6(prefix, fileNameIn, fileNameOut):
    global allCount
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
            allCount = allCount + i
            if allCount >= LIMIT_GENERATION:
                break
            i = 0
        mac = f.readline().rstrip('\n')
        out.append(mac2eui64(mac=mac, prefix=prefix))
    f.close()
    writeToFile(out, fileNameOut)
    log("end generateMacInIpv6, prefix:" + str(prefix))


def getAAAARecord(domain):
    global outDomains
    try:
        result = dns.resolver.query(domain, 'AAAA')
        if result[0]:
            while True:
                if flagAAAA == False:
                    outDomains.append(result[0].address)
                    break
    except:
        return None
    return None


def parseDomain(fileNameIn, fileNameOut):
    global outDomains
    global threads
    global flagAAAA
    flagAAAA = False
    outDomains = []
    log("stat generateParseDomain")
    f = open(fileNameIn)
    domain = f.readline().rstrip('\n')
    # i = 0
    progress = 0
    while domain:
        if (len(threads) <= 400):
            # i += 1
            # i = 0
            try:
                x = threading.Thread(target=getAAAARecord, args=(domain,))
                x.start()
                progress += 1
                threads.append(x)
                domain = f.readline().rstrip('\n')
            except:
                i = 0
                print("error Thread")

        if (len(outDomains) > COUNT_TO_WRITE):
            flagAAAA = True
            writeToFile(outDomains, fileNameOut)
            outDomains = []
            flagAAAA = False

        for idx, val in enumerate(threads):
            if val:
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
                if entry.name != '.gitignore' or entry.name != 'addressesFromDomain.txt':
                    os.remove(entry.path)
            elif entry.is_dir():
                shutil.rmtree(entry.path)


def forPrefixes(method):
    global allCount
    allCount = 0
    for prefix in prefixes:
        if method == 'WordAddresses':
            if args.wordAddresses != None:
                generateWordAddresses(prefix, FILE_HEX_WORD, OUT_DIRECTORY + "WordAddresses.txt")
                executeNmap(OUT_DIRECTORY + "WordAddresses.txt", ports)
        if method == 'MacInIpv6':
            if args.macInIpv6 != None:
                generateMacInIpv6(prefix, DATA_DIRECTORY + "mac.txt",
                                  OUT_DIRECTORY + "MacInIpv6.txt")
                executeNmap(OUT_DIRECTORY + "MacInIpv6.txt", ports)
        if method == 'ServicePort':
            if args.servicePort != None:
                generateServicePort(prefix, OUT_DIRECTORY + "ServicePort.txt")
                executeNmap(OUT_DIRECTORY + "ServicePort.txt", ports)
        if method == 'Lowbyte':
            if args.lowbyte != None:
                generateLowbyte(prefix, OUT_DIRECTORY + "Lowbyte.txt")
                executeNmap(OUT_DIRECTORY + "Lowbyte.txt", ports)
        if method == 'Ipv4InIpv6':
            if args.ipv4InIpv6 != None:
                generateIpv4InIpv6(prefix, 255, 255, 255, 255, OUT_DIRECTORY + "Ipv4InIpv6.txt")
                executeNmap(OUT_DIRECTORY + "Ipv4InIpv6.txt", ports)
        if allCount >= LIMIT_GENERATION:
            break


parser = argparse.ArgumentParser(description='Command List')
parser.add_argument('-wordAddresses', nargs='*', help="Use method wordAddresses to generate")
parser.add_argument("-macInIpv6", nargs='*', help="Use method macInIpv6 to generate")
parser.add_argument("-servicePort", nargs='*', help="Use method servicePort to generate")
parser.add_argument("-lowbyte", nargs='*', help="Use method lowbyte to generate")
parser.add_argument("-ipv4InIpv6", nargs='*', help="Use method ipv4InIpv6 to generate")
parser.add_argument("-generateMacAddresses", nargs='*', help="Generate a list of mac addresses")
parser.add_argument("-parseDomain", nargs='*', help="Parse IPv6 list from domain list data/domains.txt")
parser.add_argument("-ports", nargs='?', help="list of ports that will be used in the scanner, example:-ports 80,443")
parser.add_argument("-clearOutput", nargs='*', help="Сlear output directory")
parser.add_argument("-clearOutputNmap", nargs='*', help="Сlear output nmap directory")
parser.add_argument("-countToWrite", nargs='*', help="Buffer addresses for writing, default 1000")
parser.add_argument("-nmapScan", nargs='*',
                    help="-nmapScan <directory> Nmap custom, scan all files in directory, default <directory> : out ")
parser.add_argument("-executeNmap", nargs='*',
                    help="-executeNmap 0|1 scan ipv6 addresses after generate? 0 - no, 1 - yes, default 0")
parser.add_argument("-limitGenerate", nargs='*', help="Limit of generate IPv6 addresses")
parser.add_argument("-prefixFile", nargs='*',
                    help="File to the prefix list. Example: '-prefixFile data/domains_alexa_topIPV6.txt'")

# -nmapScan dataIn
# -prefixFile data/domains_alexa_topIPV6_zakres_2.txt -wordAddresses -servicePort -lowbyte -ipv4InIpv6 -macInIpv6 -ports 80,21,22,443 -countToWrite 1000 -limitGenerate 131072 -executeNmap 0
# -wordAddresses -servicePort -lowbyte -ipv4InIpv6 -macInIpv6 -ports 80,21,22,443 -countToWrite 1000 -limitGenerate 262144 -executeNmap 0
# -generateMacAddresses
args = parser.parse_args()
log("start program")
ports = [80]
if args.ports != None:
    ports = args.ports.split(",")

if args.prefixFile != None:
    FILE_PREFIX_LIST = args.prefixFile[0]

if args.nmapScan != None:
    if args.nmapScan[0]:
        nmapDirectoryIn = args.nmapScan[0]
    else:
        nmapDirectoryIn = OUT_DIRECTORY
    entries = os.scandir(nmapDirectoryIn)
    for entry in entries:
        if entry.name != ".gitignore":
            executeNmapPath(entry, OUT_NMAP_DIRECTORY, ports)

if args.countToWrite != None:
    COUNT_TO_WRITE = int(args.countToWrite[0])

if args.limitGenerate != None and int(args.limitGenerate[0]) > 0:
    LIMIT_GENERATION = int(args.limitGenerate[0])

if args.clearOutput != None:
    clear(OUT_DIRECTORY)

if args.clearOutputNmap != None:
    clear(OUT_NMAP_DIRECTORY)

if args.generateMacAddresses != None:
    geneareMacAddresses()

if args.parseDomain != None:
    parseDomain(FILE_DOMAINS, FILE_PREFIX_LIST)

if args.wordAddresses != None or args.macInIpv6 != None or args.servicePort != None or args.lowbyte != None or args.ipv4InIpv6 != None:
    prefixes = readPrefixes(FILE_PREFIX_LIST)
    forPrefixes('WordAddresses')
    forPrefixes('MacInIpv6')
    forPrefixes('ServicePort')
    forPrefixes('Lowbyte')
    forPrefixes('Ipv4InIpv6')
