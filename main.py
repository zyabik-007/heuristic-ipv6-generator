from datetime import datetime
import os
import re
import ipaddress

COUNT_TO_WRITE = 1000

OUT_NMAP_DIRECTORY = "outNmap/"
OUT_DIRECTORY = "out/"
DATA_DIRECTORY = "data/"

FILE = OUT_DIRECTORY + "ip.txt"
FILE_PREFIX_LIST = DATA_DIRECTORY + "list-prefixes.txt"
FILE_HEX_WORD = DATA_DIRECTORY + "hex-wordy-en.txt"


def generateAddresses(address, length, fileNameOut):
    log("stat generateAddresses, address:" + address)
    length += 1
    out = []
    i = 0
    ip = ipaddress.IPv6Address(ipaddress.IPv6Network(address).network_address.exploded)
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
        f.write(str(ip) + '\n')


def remove_duplicates(raw_file):
    addrs = raw_file.readlines()
    # convert str to IPv6 object
    for i in range(len(addrs)):
        # strict implicitly set to true, no host bits allowed to be set
        addrs[i] = ipaddress.IPv6Network(addrs[i][:-1])
    uniques = set(addrs)
    return uniques


def find_subsets(addr_set):
    subsets = {}
    for x in addr_set:
        for y in addr_set:
            if x.overlaps(y) and x != y:
                # print("overlap between %s and %s" % (x, y))
                # if prefix for y is larger than prefix for x, addr range y is a subset of addr range x
                if x.prefixlen < y.prefixlen:
                    subsets.setdefault(x, [])
                    # if y is already a key, then y has advertised subranges - there is a chain here
                    # (eg. /32 containing /40 containing /48)
                    if y in subsets.keys():
                        # print("\n\n\ny-based chain found:\nx: %s\ny: %s" % (subsets[x], subsets[y]))
                        subsets[x].append([y, subsets[y]])
                        # print("key %s: val %s" % (x, subsets[x]))
                        del subsets[y]
                    else:
                        subsets[x].append(y)
                else:
                    subsets.setdefault(y, [])
                    # same chain check as above
                    if x in subsets.keys():
                        # print("\n\n\nx-based chain found:\nx: %s\ny: %s" % (subsets[x], subsets[y]))
                        subsets[y].append([x, subsets[x]])
                        # print("key %s: val %s" % (y, subsets[y]))
                        del subsets[x]
                    else:
                        subsets[y].append(x)
    return subsets


def readPrefixes(fileName):
    f = open(fileName)
    uniques = remove_duplicates(f)
    f.close()
    subsets = find_subsets(uniques)
    return subsets


def generateIpv4InIpv6(prefix, aLim=255, bLim=255, cLim=255, dLim=255, fileNameOut=""):
    log("stat generateIpv4InIpv6, prefix:" + prefix)
    aLim += 1
    bLim += 1
    cLim += 1
    dLim += 1
    out = []
    i = 0
    b = 0
    c = 0
    d = 0
    ip = ipaddress.IPv6Network(ipaddress.IPv6Network(prefix).network_address.exploded + "/32").network_address

    for a in range(aLim):
        for b in range(bLim):
            for c in range(cLim):
                for d in range(dLim):
                    i += 1
                    out.append(str(ip) + str(a) + ":" + str(b) + ":" + str(c) + ":" + str(d))
                    if (i > COUNT_TO_WRITE):
                        writeToFile(out, fileNameOut)
                        out = []
                        i = 0
    writeToFile(out, fileNameOut)


def generateLowbyte(prefix, fileNameOut):
    log("stat generateLowbyte, prefix:" + prefix)
    generateAddresses(prefix, 255, fileNameOut)


def generateServicePort(prefix, fileNameOut):
    log("stat generateServicePort, prefix:" + prefix)
    out = []
    ports = [20, 21, 22, 23, 25, 53, 80, 8080, 110, 119, 123, 135, 139, 143, 161, 194, 443, 445, 993, 995, 1723, 3306,
             5900, 3389]
    ip = ipaddress.IPv6Address(ipaddress.IPv6Network(prefix).network_address.exploded)
    for port in ports:
        out.append(ip + port)
    writeToFile(out, fileNameOut)


def mac2eui64(mac, prefix=None):
    eui64 = re.sub(r'[.:-]', '', mac).lower()
    eui64 = eui64[0:6] + 'fffe' + eui64[6:]
    eui64 = hex(int(eui64[0:2], 16) ^ 2)[2:].zfill(2) + eui64[2:]

    if prefix is None:
        return ':'.join(re.findall(r'.{4}', eui64))
    else:
        try:
            net = ipaddress.ip_network(prefix, strict=False)
            euil = int('0x{0}'.format(eui64), 16)
            return str(net[euil])
        except:  # pylint: disable=bare-except
            return


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
    log("stat generateWordAdresses, prefix:" + prefix)
    f = open(fileNameIn)
    words = f.read().splitlines()
    ip = ipaddress.ip_network(prefix, strict=False).network_address.exploded
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


def log(text):
    f = open("logs.txt", "w+")
    f.write(getDateTime() + " " + text + "\n")
    f.close()


if False:
    subsets = readPrefixes(FILE_PREFIX_LIST)
    for ip in subsets:
        ip = '2402:e100::/32'
        generateWordAdresses(ip, FILE_HEX_WORD, OUT_DIRECTORY + "WordAdresses.txt")
        mac2eui64(mac='06:b2:4a:00:00:9f', prefix=ip)
        generateServicePort(ip, OUT_DIRECTORY + "ServicePort.txt")
        generateLowbyte(ip, OUT_DIRECTORY + "Lowbyte.txt")
        generateIpv4InIpv6(ip, 0, 0, 0, 5, OUT_DIRECTORY + "Ipv4InIpv6.txt")
        generateAddresses('2402:e100:0:0:0:0:0:0/112', 10)
        break

if True:
    ports = [80]
    executeNamp(OUT_DIRECTORY + "WordAdresses.txt", ports)
    executeNamp(OUT_DIRECTORY + "ServicePort.txt", ports)
    executeNamp(OUT_DIRECTORY + "Lowbyte.txt", ports)
    executeNamp(OUT_DIRECTORY + "Ipv4InIpv6.txt", ports)
