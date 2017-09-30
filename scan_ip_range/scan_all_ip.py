#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import time
import threading
from ip_utils import *
from check_gae import check_gae
from merge_ip_range import *

sys.dont_write_bytecode = True

g_infile = 'ip_range_in.txt'
g_outfile = 'ip_list_out.txt'

sub_ip_range = []
g_per_save_num = 10
g_save_interval = 60 * 10
g_threads = 1


wLock = threading.Lock()


def save_ip(ip_list, file=g_outfile):
    with wLock:
        with open(file, 'a') as f:
            for ip in ip_list:
                f.write(ip)
                f.write('\n')


class gae_scanner(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.sub_addr = 0
        self.ip_list = []
        self.last_save_time = time.time()

    def save_data(self):
        if len(self.ip_list) == 0:
            return

        save_ip(self.ip_list)
        self.ip_list = []

    def run(self,
            per_save_num=g_per_save_num,
            save_interval=g_save_interval):

        while True:

            try:
                b, e = sub_ip_range.pop()
                print("left range num:%d" % len(sub_ip_range))
            except Exception as e:
                self.save_data()
                return

            for ip_int in range(b, e+1):
                ip = ip_num_to_string(ip_int)

                try:
                    is_gae = check_gae(ip)
                    if is_gae:
                        self.ip_list.append(ip)

                        if len(self.ip_list) >= per_save_num:
                            self.save_data()
                            self.last_save_time = time.time()

                except Exception as e:
                    print('Error occur: %r' % e)
                    continue


def main():
    global sub_ip_range
    ip_range = load_ip_range(g_infile)
    input_ip_num = count_range_ip_num(ip_range)
    print("input range num:%d, ip num:%d" % (len(ip_range), input_ip_num))

    ip_range = merge_range(ip_range)
    print("merge to %d" % len(ip_range))

    input_bad_ip_range_lines = load_bad_ip_range()
    bad_range_list = parse_range_string(input_bad_ip_range_lines)
    bad_range_list = merge_range(bad_range_list)

    ip_range_list = filter_ip_range(ip_range, bad_range_list)
    left_ip_num = count_range_ip_num(ip_range_list)
    print("left %d ips after filter bad ip" % left_ip_num)

    sub_ip_range = split_range_to_24(ip_range_list)
    sub_range_ip_num = count_range_ip_num(sub_ip_range)
    print("convert to %d /24 ranges, ip num:%d" % (len(sub_ip_range), sub_range_ip_num))

    threads_list = []
    for i in range(g_threads):
        scanner = gae_scanner()
        scanner.setDaemon(True)
        scanner.start()
        threads_list.append(scanner)
    for p in threads_list:
        p.join()


if __name__ == '__main__':
    main()
