# dnslog

## Information

Minimalistic DNS logging application. Captures all DNS traffic and stores its textual presentation to the `/var/log/dnslog/<date>.log.gz`.

```
$ zcat 2018-07-12.log.gz | head
00:00:00.001595 R A 192.168.107.168 192.168.110.233 ocsp.verisign.com 23.37.43.27
00:00:00.001949 Q PTR 192.168.107.146 199.253.182.182 2.6.e.f.a.b.e.f.f.f.6.5.0.5.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa ?
00:00:00.002314 R AAAA 37.48.122.173 194.5.87.10 nsres1.shockmedia.nl -
00:00:00.002321 R AAAA 37.48.122.173 194.5.87.10 nsres1.shockmedia.nl -
00:00:00.003777 Q A 192.168.105.140 192.168.107.168 stats.l.doubleclick.net ?
00:00:00.005158 R A 192.168.107.168 192.168.105.140 stats.l.doubleclick.net 173.194.76.155,173.194.76.156,173.194.76.154,173.194.76.157
00:00:00.010956 Q * 192.168.110.233 192.168.107.168 star-ds.trendmicro.com.edgekey.net ?
00:00:00.010969 Q * 192.168.110.233 192.168.107.168 star-ds.trendmicro.com.edgekey.net ?
00:00:00.011887 Q A 194.5.87.10 198.6.1.161 dnsdfwspa04.dfw9.maint.ops.us.uu.net ?
00:00:00.011896 Q AAAA 194.5.87.10 198.6.1.161 dnsdfwspa04.dfw9.maint.ops.us.uu.net ?
```

## Prerequisites

`python2`, `pcapy`, `dpkt`

## Installation
1) `cd /opt`
2) `sudo apt-get install python python-pcapy python-dpkt`
3) `git clone https://github.com/stamparm/dnslog.git`
4) `sudo crontab -e  # append the following line`

`*/1 * * * * if [ -n "$(ps -ef | grep -v grep | grep 'dnslog.py')" ]; then : ; else python /opt/dnslog/dnslog.py; fi`
