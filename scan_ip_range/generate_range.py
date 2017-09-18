#!/usr/bin/env python3

import os
import sys
import re
from functools import reduce


def ipRange(start_ip, end_ip):
    # http://cmikavac.net/2011/09/11/how-to-generate-an-ip-range-list-in-python/
    start = list(map(int, start_ip.split(".")))
    end = list(map(int, end_ip.split(".")))
    temp = start
    ip_range = []

    ip_range.append(start_ip)
    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i - 1] += 1
        ip_range.append(".".join(map(str, temp)))

    return ip_range


# https://github.com/moonshawdo/checkgoogleip
# moonshawdo@gamil.com

def from_string(s):
    """Convert dotted IPv4 address to integer."""
    return reduce(lambda a, b: a << 8 | b, map(int, s.split(".")))


def to_string(ip):
    """Convert 32-bit integer to dotted IPv4 address."""
    return ".".join(map(lambda n: str(ip >> n & 0xFF), [24, 16, 8, 0]))


g_ipcheck = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')


def checkipvalid(ip):
    """检查ipv4地址的合法性"""
    ret = g_ipcheck.match(ip)
    if ret is not None:
        "each item range: [0,255]"
        for item in ret.groups():
            if int(item) > 255:
                return 0
        return 1
    else:
        return 0


def splitip(strline):
    """从每组地址中分离出起始IP以及结束IP"""
    begin = ""
    end = ""
    if "-" in strline:
        "xxx.xxx.xxx.xxx-xxx.xxx.xxx.xxx"
        begin, end = strline.split("-")
        if 1 <= len(end) <= 3:
            prefix = begin[0:begin.rfind(".")]
            end = prefix + "." + end
    elif strline.endswith("."):
        "xxx.xxx.xxx."
        begin = strline + "0"
        end = strline + "255"
    elif "/" in strline:
        "xxx.xxx.xxx.xxx/xx"
        (ip, bits) = strline.split("/")
        if checkipvalid(ip) and (0 <= int(bits) <= 32):
            orgip = from_string(ip)
            end_bits = (1 << (32 - int(bits))) - 1
            begin_bits = 0xFFFFFFFF ^ end_bits
            begin = to_string(orgip & begin_bits)
            end = to_string(orgip | end_bits)
    else:
        "xxx.xxx.xxx.xxx"
        begin = strline
        end = strline

    return begin, end


ipfile = "ip_range1.txt"
tmpfile = "test_tmp.txt"
iplineslist = []
ipend = "0/24"
iptmp = []
wtmp = []

if os.path.exists(ipfile):
    try:
        fp = open(ipfile, "r")
        linecnt = 0
        for line in fp:
            data = line.strip("\r\n")
            iplineslist.append(data)
            linecnt += 1
        fp.close()
        print("load extra ip ok,line:%d" % linecnt)
    except Exception as e:
        print("load extra ip file error:%s " % str(e))
        sys.exit(1)

    with open(tmpfile, "w") as tmpfd:
        linecnt = 0
        writelinecnt = 0
        for iplines in iplineslist:
            if len(iplines) == 0 or iplines[0] == '#':
                continue
            singlelist = []
            ips = re.split(",|\|", iplines)
            for line in ips:
                if len(line) == 0 or line[0] == '#':
                    continue
                begin, end = splitip(line)
                if checkipvalid(begin) == 0 or checkipvalid(end) == 0:
                    print("ip format is error,line:%s, begin: %s,end: %s" %
                          (line, begin, end))
                    continue
                ip_range = ipRange(begin, end)
                for ip in ip_range:
                    ipPrefix = ip[0:ip.rfind(".")]
                    tmp = ipPrefix + "." + ipend
                    iptmp.append(tmp)
                    linecnt += 1
        for t in iptmp:
            if t not in wtmp:
                wtmp.append(t)
                tmpfd.write(t)
                tmpfd.write("\n")
                writelinecnt += 1
        print("splitip ip ok, line: %d" % linecnt)
        print("write ip ok, line: %d" % writelinecnt)
