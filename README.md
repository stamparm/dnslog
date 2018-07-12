# dnslog

## Information

Minimalistic DNS logging tool. Captures all DNS traffic and stores its textual presentation (in compressed form) to the `/var/log/dnslog/<date>.log.gz`. Created for the network forensics purposes.

```
$ zcat /var/log/dnslog/2018-07-12.log.gz | head
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

## Examples

* Find all DNS (`A`) requests for (malicious) domain `a3ax.dip.jp` on date `2018-07-10`:

```
$ zcat /var/log/dnslog/2018-07-10.log.gz | grep "Q A" | grep a3ax.dip.jp
07:35:55.505057 Q A 192.168.108.98 192.168.107.168 a3ax.dip.jp ?
07:35:55.506583 Q A 192.168.107.146 27.120.88.165 a3ax.dip.jp ?
07:35:55.882518 Q A 192.168.107.146 27.120.88.165 a3ax.dip.jp ?
08:04:10.402277 Q A 192.168.108.98 192.168.107.169 a3ax.dip.jp ?
08:04:10.402851 Q A 192.168.107.146 192.249.78.205 a3ax.dip.jp ?
09:04:10.381832 Q A 192.168.108.98 192.168.107.168 a3ax.dip.jp ?
09:04:10.383926 Q A 192.168.107.146 192.249.78.205 a3ax.dip.jp ?
10:04:09.247864 Q A 192.168.108.98 192.168.107.168 a3ax.dip.jp ?
10:04:09.249246 Q A 192.168.107.146 27.120.88.165 a3ax.dip.jp ?
10:04:09.838727 Q A 192.168.107.146 27.120.88.165 a3ax.dip.jp ?
10:04:10.428435 Q A 192.168.107.146 192.249.78.205 a3ax.dip.jp ?
11:04:09.719029 Q A 192.168.108.98 192.168.107.169 a3ax.dip.jp ?
11:04:09.721314 Q A 192.168.107.146 27.120.88.165 a3ax.dip.jp ?
12:04:10.857112 Q A 192.168.108.98 192.168.107.168 a3ax.dip.jp ?
12:04:10.859778 Q A 192.168.107.146 27.120.88.165 a3ax.dip.jp ?
12:04:11.582157 Q A 192.168.107.146 27.120.88.165 a3ax.dip.jp ?
12:04:12.306059 Q A 192.168.107.146 192.249.78.205 a3ax.dip.jp ?
13:04:09.110878 Q A 192.168.108.98 192.168.107.169 a3ax.dip.jp ?
13:04:09.113022 Q A 192.168.107.146 192.249.78.205 a3ax.dip.jp ?
14:04:09.491329 Q A 192.168.108.98 192.168.107.168 a3ax.dip.jp ?
14:04:09.494312 Q A 192.168.107.146 203.119.40.1 a3ax.dip.jp ?
14:04:09.766260 Q A 192.168.107.146 192.249.78.205 a3ax.dip.jp ?
```

* Find all successful DNS (`A`) replies for dynamic domains `dyndns.org` on date `2018-07-10`:

```
$ zcat /var/log/dnslog/2018-07-10.log.gz | grep "R A" | grep dyndns.org | grep -v -E " -$"
00:03:51.983455 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
00:15:18.533338 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
00:26:33.771922 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
00:38:00.242124 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
00:49:15.570793 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
01:00:42.181528 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
01:11:57.469337 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
01:23:12.772092 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
01:34:39.379240 R A 192.168.107.169 192.168.110.232 members.dyndns.org 162.88.175.12
01:46:05.788148 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
01:57:21.114593 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
02:08:36.351852 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
02:19:51.655763 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
02:31:06.892700 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
02:42:33.579657 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
02:53:48.914302 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
03:05:15.324097 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
03:16:41.901465 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
03:27:57.201255 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
03:39:23.688141 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
03:50:39.164092 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
04:01:54.377031 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
04:02:32.902917 R A 208.76.58.1 192.168.110.82 cn-dns1.dyndns.org 80.89.176.10
04:02:32.902944 R A 208.76.58.1 192.168.110.82 cn-dns1.dyndns.org 80.89.176.10
04:02:32.903559 R A 208.76.58.1 192.168.110.82 cn-dns2.dyndns.org 80.89.176.11
04:02:32.903581 R A 208.76.58.1 192.168.110.82 cn-dns2.dyndns.org 80.89.176.11
04:13:09.701765 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
04:24:24.996081 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
04:34:56.750744 R A 8.8.8.8 192.168.104.184 checkip.dyndns.org 162.88.100.200,216.146.43.71,162.88.96.194,216.146.38.70,131.186.113.135,131.186.113.136
04:35:40.237989 R A 192.168.107.168 192.168.110.232 members.dyndns.org 162.88.175.12
04:40:00.188873 R A 8.8.8.8 192.168.104.184 checkip.dyndns.org 162.88.100.200,216.146.38.70,216.146.43.71,131.186.113.136,131.186.113.135,162.88.96.194
...
```

## Prerequisites

* Linux (recommended: Debian/Ubuntu)
* `python` (version 2.x)
* `pcapy`
* `dpkt`

## Installation
1) `sudo su`
2) `apt-get install git python python-pcapy python-dpkt`
3) `cd /opt`
4) `git clone --depth 1 https://github.com/stamparm/dnslog.git`
5) `crontab -e`  # append the following line

`*/1 * * * * if [ -n "$(ps -ef | grep -v grep | grep 'dnslog.py')" ]; then : ; else python /opt/dnslog/dnslog.py &> /var/log/dnslog.log; fi`
