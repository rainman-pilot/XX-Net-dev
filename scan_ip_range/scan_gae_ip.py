#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
sys.dont_write_bytecode = True

try:
    import gevent
    import gevent.monkey
    gevent.monkey.patch_all(os=False, signal=False, subprocess=False)
except ImportError:
    print('Could not find gevent! Please install gevent-1.0.0 or above.\n'
          'Exit...')
    sys.exit(-1)

try:
    import OpenSSL
except ImportError:
    print('Could not find pyOpenSSL! Please install pyOpenSSL-16.0.0 or above.\n'
          'Exit...')
    sys.exit(-1)

# Scan config start
import os
dir = os.path.abspath(os.path.dirname(__file__))
g_outfile = 'ip_out.txt'
g_skip_ipdb_file = 'directip.db'
g_outfile = os.path.join(dir, g_outfile)
g_skip_ipdb_file = os.path.join(dir, g_skip_ipdb_file)
g_per_save_num = 100
g_save_interval = 60 * 10
g_threads = 500
g_timeout = 4
g_conn_timeout = 1
g_handshake_timeout = 1.5
g_server_name = b'www.google.com'
g_http_req = (
    b'HEAD / HTTP/1.1\r\n'
    b'Host: www.appspot.com\r\n'
    b'Connection: Close\r\n\r\n'
    )
gws_ciphers = (
    'TLSv1.2:'
    '!ECDHE-RSA-AES128-GCM-SHA256:'
    '!AES128-GCM-SHA256:'
    '!aNULL:!eNULL:!MD5:!DSS:!RC4:!3DES'
    )
GoogleG23PKP = set((
# https://pki.google.com/GIAG2.crt
b'''\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnCoEd1zYUJE6BqOC4NhQ
SLyJP/EZcBqIRn7gj8Xxic4h7lr+YQ23MkSJoHQLU09VpM6CYpXu61lfxuEFgBLE
XpQ/vFtIOPRT9yTm+5HpFcTP9FMN9Er8n1Tefb6ga2+HwNBQHygwA0DaCHNRbH//
OjynNwaOvUsRBOt9JN7m+fwxcfuU1WDzLkqvQtLL6sRqGrLMU90VS4sfyBlhH82d
qD5jK4Q1aWWEyBnFRiL4U5W+44BKEMYq7LqXIBHHOZkQBKDwYXqVJYxOUnXitu0I
yhT8ziJqs07PRgOXlwN+wLHee69FM8+6PnG33vQlJcINNYmdnfsOEXmJHjfFr45y
aQIDAQAB
-----END PUBLIC KEY-----
''',
# https://pki.goog/gsr2/GIAG3.crt
# https://pki.goog/gsr2/GTSGIAG3.crt
b'''\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAylJL6h7/ziRrqNpyGGjV
Vl0OSFotNQl2Ws+kyByxqf5TifutNP+IW5+75+gAAdw1c3UDrbOxuaR9KyZ5zhVA
Cu9RuJ8yjHxwhlJLFv5qJ2vmNnpiUNjfmonMCSnrTykUiIALjzgegGoYfB29lzt4
fUVJNk9BzaLgdlc8aDF5ZMlu11EeZsOiZCx5wOdlw1aEU1pDbcuaAiDS7xpp0bCd
c6LgKmBlUDHP+7MvvxGIQC61SRAPCm7cl/q/LJ8FOQtYVK8GlujFjgEWvKgaTUHF
k5GiHqGL8v7BiCRJo0dLxRMB3adXEmliK+v+IO9p+zql8H4p7u2WFvexH6DkkCXg
MwIDAQAB
-----END PUBLIC KEY-----
''',
# https://pki.goog/gsr4/GIAG3ECC.crt
b'''\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEG4ANKJrwlpAPXThRcA3Z4XbkwQvW
hj5J/kicXpbBQclS4uyuQ5iSOGKcuCRt8ralqREJXuRsnLZo0sIT680+VQ==
-----END PUBLIC KEY-----
'''))
g_context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
g_context.set_session_cache_mode(OpenSSL.SSL.SESS_CACHE_OFF)
g_context.set_cipher_list(gws_ciphers)
# Scan config end

# Load/Save scan data function start
import socket
import struct
import threading

class SkipIPv4Database:
    # Code from:
    #    https://github.com/SeaHOH/GotoX/blob/master/local/common/region.py
    # Data builder:
    #    github.com/SeaHOH/GotoX/blob/master/launcher/buildipdb.py
    # Data from:
    #    https://raw.githubusercontent.com/SeaHOH/GotoX/master/data/directip.db
    # Original data from:
    #    https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest
    #    https://github.com/17mon/china_ip_list/raw/master/china_ip_list.txt
    def __init__(self, filename):
        with open(filename, 'rb') as f:
            data_len, = struct.unpack('>L', f.read(4))
            index = f.read(224 * 4)
            data = f.read(data_len)
            if f.read(3) != b'end':
                raise ValueError("The %s file's data is broken! "
                                 'Please check or downloads again.'
                                 % filename)
            self.update = f.read().decode('ascii')
        self.index = struct.unpack('>' + 'h' * (224 * 2), index)
        self.data = struct.unpack('4s' * (data_len // 4), data)

    def __contains__(self, ip, inet_aton=socket.inet_aton):
        nip = inet_aton(ip)
        index = self.index
        fip = nip[0]
        if fip >= 224:
            return True
        fip *= 2
        lo = index[fip]
        if lo < 0:
            return False
        hi = index[fip + 1]
        data = self.data
        while lo < hi:
            mid = (lo + hi) // 2
            if data[mid] > nip:
                hi = mid
            else:
                lo = mid + 1
        return lo & 1

g_skip_ipdb = SkipIPv4Database(g_skip_ipdb_file)
print(g_skip_ipdb.update)

wLock = threading.Lock()
def save_ip_list(ip_list, file=g_outfile):
    with wLock:
        if not ip_list:
            return
        with open(file, 'ab') as f:
            for ip in ip_list:
                f.write(ip.encode())
                f.write(b'\n')
# Load/Save scan data function end

# Scan function start
import time
from openssl_wrap import SSLConnection

def get_ssl_socket(sock, server_hostname=None, context=g_context):
    ssl_sock = SSLConnection(context, sock)
    if server_hostname:
        ssl_sock.set_tlsext_host_name(server_hostname)
    return ssl_sock

def google_verify(sock, g23pkp=GoogleG23PKP):
    # Verify certificates for Google web sites.
    certs = sock.get_peer_cert_chain()
    if len(certs) < 3:
        raise OpenSSL.SSL.Error('No intermediate CA was found.')
    pkp = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, certs[1].get_pubkey())
    if pkp not in g23pkp:
        raise OpenSSL.SSL.Error('The intermediate CA is mismatching.')

def get_status_code(sock, http_req=g_http_req):
    sock.send(http_req)
    return sock.read(12)[-3:]

def get_ip_info(ip,
                conn_timeout=g_conn_timeout,
                handshake_timeout=g_handshake_timeout,
                timeout=g_timeout,
                server_name=g_server_name,
                offlinger_val=struct.pack('ii', 1, 0)):
    start_time = time.time()
    sock = None
    ssl_sock = None
    #domain = None
    status_code = None
    try:
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, offlinger_val)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
        ssl_sock = get_ssl_socket(sock, server_name)
        ssl_sock.settimeout(conn_timeout)
        ssl_sock.connect((ip, 443))
        ssl_sock.settimeout(handshake_timeout)
        ssl_sock.do_handshake()
        handshaked_time = time.time() - start_time
        if handshaked_time > handshake_timeout:
            raise socket.timeout('handshake cost %dms timed out' % int(handshaked_time*1000))
        ssl_sock.settimeout(timeout)
        google_verify(ssl_sock)
        #domain = ssl_sock.get_peer_certificate().get_subject().CN
        status_code = get_status_code(ssl_sock)
    except Exception as e:
        #print(e)
        pass
    finally:
        if ssl_sock:
            ssl_sock.close()
        if sock:
            sock.close()
    # Get '302' redirect when this IP provide Google App Engine server.
    return status_code == b'302'
# Scan function end

from _functools import reduce

def ip2int(ip):
    return reduce(lambda a, b: a << 8 | b, map(int, ip.split('.')))

class IPv4Generater:
    def __init__(self, ip_start=None, ip_end=None,
                 min_num=g_threads * 2,
                 max_num=g_threads * 8):
        self.Lock = threading.Lock()
        self.ip_pool = set()
        self.stoped = False
        if ip_start is None:
            ip_num = ip2int('1.0.0.0')
        else:
            ip_num = ip2int(ip_start)
        if ip_end is None:
            ip_stop_num = ip2int('224.0.0.0')
        else:
            ip_stop_num = ip2int(ip_end)
        threading._start_new_thread(self._generate_ips,
                                    (ip_num, ip_stop_num, min_num, max_num))
        time.sleep(1)

    def _generate_ips(self, ip_num, ip_stop_num, min_num, max_num,
                      pack=struct.pack,
                      inet_ntoa=socket.inet_ntoa,
                      skip_ipdb=g_skip_ipdb):
        while True:
            if len(self.ip_pool) < min_num:        
                while len(self.ip_pool) < max_num:
                    for _ in range(100):
                        if ip_num >= ip_stop_num:
                            self.stoped = True
                            break
                        ip = inet_ntoa(pack('>i', ip_num))
                        if ip not in skip_ipdb:
                            self.ip_pool.add(ip)
                        ip_num += 1
                    if self.stoped:
                        break
            if self.stoped:
                break
            time.sleep(0.01)

    def pop(self):
        with self.Lock:
            #print(len(self.ip_pool))
            if self.ip_pool or self.stoped:
                return self.ip_pool.pop()
            else:
                while True:
                    time.sleep(0.01)
                    if self.ip_pool:
                        return self.ip_pool.pop()

class GAEScanner(threading.Thread):
    Lock = threading.Lock()
    ip_generater = None

    def __init__(self, ip_generater):
        threading.Thread.__init__(self)
        if self.ip_generater is None:
            self.__class__.ip_generater = ip_generater
            self.__class__.ip_list = []
            self.__class__.is_running = True
            self.__class__.threads_num = 0
            self.run = self._save_data_interval
        else:
            self.__class__.threads_num += 1

    def stop(self):
        self.__class__.is_running = False
        self.__class__.threads_num -= 1

    def _save_data_interval(self,
                           save_interval=g_save_interval,
                           per_save_num=g_per_save_num):
        last_save_time = time.time()
        while self.is_running or self.threads_num:
            time.sleep(10)
            try:
                with self.Lock:
                    num = len(self.ip_list)
                    now = time.time()
                    is_save = (num >= per_save_num or
                               num and
                               now - last_save_time > save_interval)
                    if is_save:
                        ip_list = self.ip_list
                        self.__class__.ip_list = []
                if is_save:
                    save_ip_list(ip_list)
                    last_save_time = now
            except Exception:
                pass
        self.__class__.ip_generater = None
        if self.ip_list:
            save_ip_list(self.ip_list)

    def run(self):
        while True:
            try:
                ip = self.ip_generater.pop()
                #time.sleep(0.5)
                #print(ip)
                #continue
                is_gae = get_ip_info(ip)
                if is_gae:
                    with self.Lock:
                        self.ip_list.append(ip)
                    print("%s is ok" % ip)
            except KeyError:
                self.stop()
                break
            except Exception as e:
                print('Error occur: %r' % e)
                continue

def main(ip_start=None, ip_end=None):
    ip_generater = IPv4Generater(ip_start, ip_end)
    threads_list = []
    for i in range(g_threads + 1):
        scanner = GAEScanner(ip_generater)
        scanner.setDaemon(True)
        #scanner.setName('SCANNER%s' % str(i).rjust(4, '0'))
        scanner.start()
        threads_list.append(scanner)
    for p in threads_list:
        p.join()
    print('scan over.')

if __name__ == '__main__':
    main()
