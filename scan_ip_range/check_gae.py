#!/usr/bin/env python2
# coding:utf-8
import sys
import os

import OpenSSL
import time
import socket
import struct
from openssl_wrap import SSLConnection
import xlog

g_timeout = 10
g_conn_timeout = 5
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


def check_return(sock, http_req=g_http_req):
    sock.send(http_req)

    # Return '302' redirect when the IP provide Google App Engine server.
    g_redirect_str = (
        b'302 Found\r\n'
        b'Location: https://console.cloud.google.com/appengine'
    )
    return sock.read(72)[-63:] == g_redirect_str


def check_gae(ip,
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
        is_gae = check_return(ssl_sock)
        return is_gae
    except Exception as e:
        #print(e)
        pass
    finally:
        if ssl_sock:
            ssl_sock.close()
        if sock:
            sock.close()

    return False


if __name__ == '__main__':
    if len(sys.argv) > 1:
        ip = sys.argv[1]
        xlog.info("test ip:%s", ip)
        res = check_gae(ip)
        if not res:
            print("check fail")
        else:
            print("check success")
    else:
        xlog.info("check_ip <ip>")
