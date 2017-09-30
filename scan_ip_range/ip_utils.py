#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'moonshawdo@gamil.com'

import re


def ip_string_to_num(s):
    """Convert dotted IPv4 address to integer."""
    return reduce(lambda a, b: a << 8 | b, map(int, s.split(".")))


def get_ip_maskc(ip_str):
    head = ".".join(ip_str.split(".")[:-1])
    return head + ".0"


def ip_num_to_string(ip):
    """Convert 32-bit integer to dotted IPv4 address."""
    return ".".join(map(lambda n: str(ip >> n & 0xFF), [24, 16, 8, 0]))


g_ip_check = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')


def check_ip_valid(ip):
    """检查ipv4地址的合法性"""
    ret = g_ip_check.match(ip)
    if ret is not None:
        "each item range: [0,255]"
        for item in ret.groups():
            if int(item) > 255:
                return 0
        return 1
    else:
        return 0


def is_valid_ipv6(ip):
    """Copied from http://stackoverflow.com/a/319293/2755602"""
    """Validates IPv6 addresses.
    """
    pattern = re.compile(r"""
        ^
        \s*                         # Leading whitespace
        (?!.*::.*::)                # Only a single whildcard allowed
        (?:(?!:)|:(?=:))            # Colon iff it would be part of a wildcard
        (?:                         # Repeat 6 times:
            [0-9a-f]{0,4}           #   A group of at most four hexadecimal digits
            (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
        ){6}                        #
        (?:                         # Either
            [0-9a-f]{0,4}           #   Another group
            (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
            [0-9a-f]{0,4}           #   Last group
            (?: (?<=::)             #   Colon iff preceeded by exacly one colon
             |  (?<!:)              #
             |  (?<=:) (?<!::) :    #
             )                      # OR
         |                          #   A v4 address with NO leading zeros
            (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
            (?: \.
                (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
            ){3}
        )
        \s*                         # Trailing whitespace
        $
    """, re.VERBOSE | re.IGNORECASE | re.DOTALL)
    return pattern.match(ip) is not None


def check_ip_valid6(ip):
    """检查ipv6地址的合法性"""
    if is_valid_ipv6(ip):
        return 1
    else:
        return 0


def parse_ip_range_line(strline):
    """从每组地址中分离出起始IP以及结束IP"""
    begin = ""
    end = ""
    if "-" in strline:
        num_regions = strline.split(".")
        if len(num_regions) == 4:
            "xxx.xxx.xxx-xxx.xxx-xxx"
            begin = ''
            end = ''
            for region in num_regions:
                if '-' in region:
                    s, e = region.split('-')
                    begin += '.' + s
                    end += '.' + e
                else:
                    begin += '.' + region
                    end += '.' + region
            begin = begin[1:]
            end = end[1:]

        else:
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
        if check_ip_valid(ip) and (0 <= int(bits) <= 32):
            orgip = ip_string_to_num(ip)
            end_bits = (1 << (32 - int(bits))) - 1
            begin_bits = 0xFFFFFFFF ^ end_bits
            begin = ip_num_to_string(orgip & begin_bits)
            end = ip_num_to_string(orgip | end_bits)
    else:
        "xxx.xxx.xxx.xxx"
        begin = strline
        end = strline

    return begin, end


def parse_range_string(input_lines):
    ip_range_list = []

    ip_lines_list = re.split("\r|\n", input_lines)
    for raw_line in ip_lines_list:
        raw_s = raw_line.split("#")
        context_line = raw_s[0]

        context_line = context_line.replace(' ', '')

        ips = re.split(",|\|", context_line)
        for line in ips:
            if len(line) == 0:
                # print "non line:", line
                continue
            begin, end = parse_ip_range_line(line)
            if check_ip_valid(begin) == 0 or check_ip_valid(end) == 0:
                print("ip format is error,line:%s, begin: %s,end: %s" % (line, begin, end))
                continue
            nbegin = ip_string_to_num(begin)
            nend = ip_string_to_num(end)
            ip_range_list.append([nbegin, nend])
            # print begin, end

    ip_range_list.sort()

    return ip_range_list


def load_ip_range(input_file):
    with open(input_file, "r") as inf:
        input_good_range_lines = inf.read()
        return parse_range_string(input_good_range_lines)


def split_range_to_24(range_list):
    idr_dict = {}
    for b, e in range_list:
        b1 = int(b / 256)
        e1 = int(e / 256)
        for idr in range(b1, e1+1):
            idr_dict[idr] = 1

    out_list = []
    for idr in idr_dict:
        out_list.append((idr * 256, idr * 256 + 255))

    return out_list


def count_range_ip_num(ip_ranges):
    num = 0
    for b, e in ip_ranges:
        num += e - b + 1

    return num


if __name__ == '__main__':
    ip = "192.168.0.1"
    ip_int = ip_string_to_num(ip)
    ip_begin = (ip_int/256) * 256
    ip_end = (ip_int/256) * 256 + 255

    ip_begin = ip_num_to_string(ip_begin)
    ip_end = ip_num_to_string(ip_end)
    print(ip_begin, ip_end)