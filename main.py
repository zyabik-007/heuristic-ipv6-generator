import shutil
from datetime import datetime
import os
import ipaddress
import argparse
import dns.resolver

COUNT_TO_WRITE = 5

OUT_NMAP_DIRECTORY = "outNmap/"
OUT_DIRECTORY = "out/"
DATA_DIRECTORY = "data/"

FILE_PREFIX_LIST = DATA_DIRECTORY + "ipv6-prefix.txt"
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


def generateLowbyte(prefix, fileNameOut):
    log("stat generateLowbyte, prefix:" + str(prefix))
    generateSequenceAddresses(prefix, 255, fileNameOut)


def generateServicePort(prefix, fileNameOut):
    log("stat generateServicePort, prefix:" + str(prefix))
    out = []
    ports = [20, 21, 22, 23, 25, 53, 80, 8080, 110, 119, 123, 135, 139, 143, 161, 194, 443, 445, 993, 995, 1723, 3306,
             5900, 3389]
    ip = getIp(prefix)
    for port in ports:
        out.append(ip + port)
    writeToFile(out, fileNameOut)


def mac2eui64(mac, prefix=None):
    mac_parts = mac.split(":")
    pfx_parts = getIp(prefix).exploded.split(":")
    eui64 = mac_parts[:3] + ["ff", "fe"] + mac_parts[3:]
    eui64[0] = "%02x" % (int(eui64[0], 16) ^ 0x02)
    ip = ":".join(pfx_parts[:4])
    for l in range(0, len(eui64), 2):
        ip += ":%s" % "".join(eui64[l:l + 2])
    return ip


def executeNamp(fileNameIn, ports):
    if not os.path.exists(OUT_NMAP_DIRECTORY):
        os.makedirs(OUT_NMAP_DIRECTORY)

    output = OUT_NMAP_DIRECTORY + "output_" + fileNameIn.split("/")[-1] + "_" + getDateTime() + ".txt"
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


def log(text):
    file = "logs.txt"
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
    f = open(FILE_MAC_PREFIX)
    line = f.readline().rstrip('\n')
    while line:
        mac = f.readline().rstrip('\n')
        geneareMac(mac, DATA_DIRECTORY + "mac.txt")
    f.close()


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


def parseDomain(fileNameIn, fileNameOut):
    log("stat generateParseDomain")
    f = open(fileNameIn)
    domain = f.readline().rstrip('\n')
    out = []
    i = 0
    while domain:
        i += 1
        if (i > COUNT_TO_WRITE):
            writeToFile(out, fileNameOut)
            out = []
            i = 0

        try:
            result = dns.resolver.query(domain, 'AAAA')
            if result[0]:
                out.append(result[0].address)
        except:
            log("domain error: " + domain)
        domain = f.readline().rstrip('\n')
    f.close()
    writeToFile(out, fileNameOut)


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

args = parser.parse_args()

ports = [80]
if args.ports != None:
    ports = args.ports.split(",")

if args.geneareMacAdresses != None:
    geneareMacAdresses()

if args.parseDomain != None:
    parseDomain(FILE_DOMAINS, OUT_DIRECTORY + "addressesFromDomain.txt")

if args.clearOutput != None:
    clear(OUT_DIRECTORY)

if args.clearOutputNmap != None:
    clear(OUT_NMAP_DIRECTORY)

prefixes = readPrefixes(FILE_PREFIX_LIST)
for prefix in prefixes:
    if args.wordAdresses != None:
        generateWordAdresses(prefix, FILE_HEX_WORD, OUT_DIRECTORY + "WordAdresses.txt")
        executeNamp(OUT_DIRECTORY + "WordAdresses.txt", ports)

    if args.macInIpv6 != None:
        generateMacInIpv6(prefix, DATA_DIRECTORY + "mac.txt", OUT_DIRECTORY + "MacInIpv6.txt")
        executeNamp(OUT_DIRECTORY + "MacInIpv6.txt", ports)

    if args.servicePort != None:
        generateServicePort(prefix, OUT_DIRECTORY + "ServicePort.txt")
        executeNamp(OUT_DIRECTORY + "ServicePort.txt", ports)

    if args.lowbyte != None:
        generateLowbyte(prefix, OUT_DIRECTORY + "Lowbyte.txt")
        executeNamp(OUT_DIRECTORY + "Lowbyte.txt", ports)

    if args.ipv4InIpv6 != None:
        generateIpv4InIpv6(prefix, 255, 255, 255, 255, OUT_DIRECTORY + "Ipv4InIpv6.txt")
        executeNamp(OUT_DIRECTORY + "Ipv4InIpv6.txt", ports)
