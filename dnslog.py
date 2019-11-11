#!/usr/bin/env python

"""
Copyright (c) 2018-2019 Miroslav Stampar
See the file 'LICENSE' for copying permission
"""

import gzip
import os
import re
import socket
import stat
import sys
import time
import traceback

sys.dont_write_bytecode = True

try:
    import dpkt
    import pcapy
except ImportError:
    exit("[x] sudo apt-get install python-pcapy python-dpkt")

NAME = "DNSlog"
LOG_DIRECTORY = "/var/log/%s" % NAME.lower()
DEFAULT_LOG_PERMISSIONS = stat.S_IREAD | stat.S_IWRITE | stat.S_IRGRP | stat.S_IROTH
CAPTURE_INTERFACE = "any"
CAPTURE_FILTER = "udp port 53"
SNAP_LEN = 65536
PROMISCUOUS_MODE = True
CAPTURE_TIMEOUT = 100  # ms
FLUSH_LOG_TIMEOUT = 10
SHOW_TRACE = False
CONSOLE_OUTPUT = False
SHOW_COUNTER = False
DNS_QUERY_LUT = {1:'A', 28:'AAAA', 18:'AFSDB', 42:'APL', 257:'CAA', 60:'CDNSKEY', 59:'CDS', 37:'CERT', 5:'CNAME', 49:'DHCID', 32769:'DLV', 39:'DNAME', 48:'DNSKEY', 43:'DS', 55:'HIP', 45:'IPSECKEY', 25:'KEY', 36:'KX', 29:'LOC', 15:'MX', 35:'NAPTR', 2:'NS', 47:'NSEC', 50:'NSEC3', 51:'NSEC3PARAM', 12:'PTR', 46:'RRSIG', 17:'RP', 24:'SIG', 6:'SOA', 33:'SRV', 44:'SSHFP', 32768:'TA', 249:'TKEY', 52:'TLSA', 250:'TSIG', 16:'TXT', 256:'URI', 255:'*', 252:'AXFR', 251:'IXFR', 41:'OPT', 99:'SPF', 38:'A6'}

_cap = None
_counter = 0
_datalink = None
_log_path = None
_log_handle = None
_flush_last = None

def get_log_handle(sec):
    global _log_path
    global _log_handle

    localtime = time.localtime(sec)
    _ = os.path.join(LOG_DIRECTORY, "%d-%02d-%02d.log.gz" % (localtime.tm_year, localtime.tm_mon, localtime.tm_mday))

    if _ != _log_path:
        if not os.path.exists(_):
            open(_, "w+").close()
            os.chmod(_, DEFAULT_LOG_PERMISSIONS)
        _log_path = _
        _log_handle = gzip.open(_log_path, "ab")

    return _log_handle

def log_write(sec, text):
    global _counter
    global _flush_last

    _counter += 1

    handle = get_log_handle(sec)

    if CONSOLE_OUTPUT:
        sys.stdout.write(text)
        sys.stdout.flush()

    elif SHOW_COUNTER:
        sys.stdout.write("\r%d" % _counter)
        sys.stdout.flush()

    handle.write(text.encode("utf8") if hasattr(text, "encode") else text)

    if _flush_last is None or (time.time() - _flush_last) >= FLUSH_LOG_TIMEOUT:
        handle.flush()
        _flush_last = time.time()

def safe_csv_value(value):
    retval = str(value or '-')
    if any(_ in retval for _ in (' ', '"')):
        retval = "\"%s\"" % retval.replace('"', '""')
    return retval

def packet_handler(header, packet):
    try:
        if _datalink == pcapy.DLT_LINUX_SLL:
            packet = packet[2:]
        eth = dpkt.ethernet.Ethernet(packet)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            ip_data = ip.data

            src_ip = socket.inet_ntoa(ip.src)   
            dst_ip = socket.inet_ntoa(ip.dst)

            if isinstance(ip_data, dpkt.udp.UDP):
                udp = ip_data
                msg = dpkt.dns.DNS(udp.data)
                sec, usec = header.getts()
                if msg.qd[0].name:
                    query = msg.qd[0].name.lower()
                    parts = query.split('.')
                    answers = []

                    if len(parts) < 2 or parts[-1].isdigit() or ".intranet." in query or any(query.endswith(_) for _ in (".guest", ".in-addr.arpa", ".local")) or re.search(r"\A\d+\.\d+\.\d+\.\d+\.", query) or re.search(r"\d+-\d+-\d+-\d+", parts[0]):  # (e.g. labos, labos.8.8.4.4, 57.8.68.217.checkpoint.com, 2-229-52-28.ip195.fastwebnet.it, dynamic-pppoe-178-141-14-141.kirov.pv.mts.ru)
                        return

                    if udp.sport == 53:
                        for an in msg.an:
                            if hasattr(an, "ip"):
                                answers.append(socket.inet_ntoa(an.ip))

                    if udp.dport == 53:
                        log_write(sec, "%s.%06d Q %s %s %s %s %s\n" % (time.strftime("%H:%M:%S", time.localtime(sec)), usec, DNS_QUERY_LUT[msg.qd[0].type], src_ip, dst_ip, safe_csv_value(query), "?"))
                    if udp.sport == 53:  # and msg.qr == dpkt.dns.DNS_A:
                        log_write(sec, "%s.%06d R %s %s %s %s %s\n" % (time.strftime("%H:%M:%S", time.localtime(sec)), usec, DNS_QUERY_LUT[msg.qd[0].type], src_ip, dst_ip, safe_csv_value(query), safe_csv_value(','.join(answers))))

    except KeyboardInterrupt:
        raise

    except:
        if SHOW_TRACE:
            traceback.print_exc()

def main():
    global _cap
    global _datalink

    for directory in ((LOG_DIRECTORY,)):
        if not os.path.isdir(directory):
            try:
                os.makedirs(directory)
            except:
                exit("[x] not enough permissions to create the directory '%s'. Please rerun with sudo/root privileges" % directory)

    print("[o] log directory '%s'" % LOG_DIRECTORY)

    print("[i] running...")

    try:
        _cap = pcapy.open_live(CAPTURE_INTERFACE, SNAP_LEN, PROMISCUOUS_MODE, CAPTURE_TIMEOUT)
        _cap.setfilter(CAPTURE_FILTER)
        _datalink = _cap.datalink()
        _cap.loop(-1, packet_handler)
    except KeyboardInterrupt:
        print("[!] Ctrl-C pressed")
    except pcapy.PcapError as ex:
        if "permission" in str(ex):
            exit("[x] not enough permissions to capture traffic. Please rerun with sudo/root privileges")
        else:
            raise

if __name__ == "__main__":
    try:
        main()
    except (SystemExit, Exception) as ex:
        print(ex)
    finally:
        if _log_handle:
            try:
                _log_handle.flush()
                _log_handle.close()
            except:
                pass
