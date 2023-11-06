# Setup Squid Proxy With Security Best Practice
[![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Fpassword123456%2Fsetup-squid-proxy-with-security-best-practice&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=hits&edge_flat=false)](https://hits.seeyoufarm.com)

- Security best practices when a squid proxy is being used as a "forward proxy"
- If you are configuring as a reverse proxy, some topics in this guide may not be applicable. We recommend cross-referencing other security guides for appropriate security hardening criteria when using Reverse Proxy.

```
# cat /etc/redhat-release
Rocky Linux release 8.8 (Green Obsidian)

# rpm -qa rpm -qa | grep squid
squid-4.15-6.module+el8.8.0+1273+55f5b063.x86_64

2023.11.04 Confirmed.
```
***

## 1. Ensure that SQUID is run using a non-privileged, dedicated service account - groups
The Squid proxy runs using the default account, which is usually named 'squid'. If the Squid proxy is not running under the 'squid' account or is being executed with root privileges, you should change it.

[ Check Item ]
- Check the Squid process account.
```bash
[root@localhost ~]# ps -ef | grep squid
root        5346       1  0 Nov03 ?        00:00:00 /usr/sbin/squid --foreground -f /etc/squid/squid.conf
squid       5349    5346  0 Nov03 ?        00:00:04 (squid-1) --kid squid-1 --foreground -f /etc/squid/squid.conf
```

[ Solution ] 
- If the process account is not 'squid,' change it to 'squid' and restart the service.
```bash
[root@localhost ~]# vim /usr/lib/systemd/system/squid.service

[Unit]
Description=Squid caching proxy
Documentation=man:squid(8)
After=network.target network-online.target nss-lookup.target

[Service]
Type=notify
LimitNOFILE=16384
PIDFile=/run/squid.pid
...
KillMode=mixed
NotifyAccess=all

User=squid   # <== Change to 'squid'
Group=squid  # <== Change to 'squid'
```
- Ensure that the 'squid' account does not have shell login permissions for regular users.
```bash
[root@localhost ~]# cat /etc/passwd | grep -i squid
squid:x:23:23::/var/spool/squid:/sbin/nologin
```


## 2. Ensure access to SQUID directories and files is restricted
Directories and configuration files related to Squid should only be accessible by the 'squid' or 'root' user. Verify and adjust permissions if other users have access to these directories and files.

[ Check Item ]
- Check the permissions for directories and files related to the Squid proxy.
```bash
[root@localhost ~]# ls -al /etc/squid/
total 72
drwxr-xr-x.  3 root root   4096 Oct 26 07:57 .
drwxr-xr-x. 87 root root   8192 Oct 20 14:06 ..
-rw-r--r--.  1 root squid   692 May 10  2021 cachemgr.conf
-rw-r--r--.  1 root root    692 May 10  2021 cachemgr.conf.default
drwxrwxr-x.  2 root root    102 Oct 26 07:56 conf.d
-rw-r--r--.  1 root root   1800 May 10  2021 errorpage.css
-rw-r--r--.  1 root root   1800 May 10  2021 errorpage.css.default
-rw-r--r--.  1 root root  12077 May 10  2021 mime.conf
-rw-r--r--.  1 root root  12077 May 10  2021 mime.conf.default
-rw-r-----.  1 root squid  1859 Oct 17 17:08 squid.conf
```

[ Solution ] 
- Ensure that directories and files are owned by the 'root' user and that other users do not have access.
```bash
[root@localhost ~]# chown root:root -R /etc/squid
[root@localhost ~]# chmod o-rwx -R /etc/squid
```


## 3. Ensure httpd_suppress_version_string directive is set to 'on'
By default, the Squid proxy displays the installed proxy version information in the Server header and on error pages. To prevent the version information from being displayed, follow these steps.

[ Check Item ]
- Check if the proxy version information is exposed in the Server header.
```bash
[root@localhost ~]# curl -i -k 127.0.0.1:3128
HTTP/1.1 400 Bad Request
Server: squid/4.15
...
```
- Also, confirm whether the proxy version information is exposed on error pages.
```bash
[root@localhost ~]# curl -i -k 127.0.0.1:3128
HTTP/1.1 400 Bad Request
...

<hr>
<div id="footer">
<p>Generated Mon, 18 Sep 2023 05:50:08 GMT by blah-proxy01 (squid/4.15)</p>
<!-- ERR_INVALID_URL -->
</div>
</body></html>
...
```

[ Solution ] 
- Prevent the version information from being displayed by setting "httpd_suppress_version_string" to "on" in the Squid configuration file. This will hide the version information in the Server header and on error pages.
```bash
[root@localhost ~]# vim /etc/squid/squid.conf
...

httpd_suppress_version_string on  # <== Add 
```


## 4. Ensure "Via" Header is removed
The "Via" header reveals information about the server that received the proxy request from the client, including the hostname and proxy version information. To remove the "Via" header, follow these steps.

[ Check Item ]
- Check if the "Via" header is present in the proxy response.
```bash
[root@localhost ~]# curl -i -k 127.0.0.1:3128
HTTP/1.1 400 Bad Request
...
Via: 1.1 blah-proxy01 (squid/4.15)
Connection: close
```

[ Solution ] 
- To prevent the "Via" header from being displayed, set the via configuration to "off" in the Squid configuration file.
```bash
[root@localhost ~]# vim /etc/squid/squid.conf
...

via off    # <== Add
```


## 5. Ensure "X-Cache, X-Cache-Lookup" Headers are removed
The "X-Cache" and "X-Cache-Lookup" headers provide information about the proxy's caching behavior. The "X-Cache" header can reveal the hostname of the proxy server and the installed proxy version, so it's a good practice to remove it.

[ Check Item ]
- Check if the "X-Cache" header is present in the proxy response.
```bash
[root@localhost ~]# curl -i -k 127.0.0.1:3128
HTTP/1.1 400 Bad Request
...

X-Cache: MISS from blah-proxy01
X-Cache-Lookup: NONE from blah-proxy01:3128
Via: 1.1 blah-proxy01 (squid/4.15)
Connection: close
```

[ Solution ] 
- To prevent the "X-Cache" and "X-Cache-Lookup" headers from being displayed, use the reply_header_access setting to deny access to these headers.
```bash
[root@localhost ~]# vim /etc/squid/squid.conf
...

reply_header_access X-Cache deny all          # <== Add
reply_header_access X-Cache-Lookup deny all   # <== Add
```

( Notes )
- Example of X-Cache Responses

ID | Value  | Description
----- | ----- | ----- 
1 | X-Cache: MISS from blah-proxy01 | Indicates that the requested resource could not be found in Squid's cache via the blah-proxy01 server, so it needs to be retrieved from the remote server for the client.
2 | X-Cache-Lookup: NONE from blah-proxy01:3128 | epresents the cache lookup result for the requested resource by Squid proxy. "NONE" indicates that Squid did not perform a cache lookup for this resource at blah-proxy01:3128. Since there is no cache lookup, it implies that the resource needs to be fetched from the remote server.


## 6. Ensure Inbound X-Forwarded-For Header is restricted
The "follow_x_forwarded_for" feature allows you to identify the client's actual IP address through the X-Forwarded-For header. <br>

It is equivalent to configuring the X-Forwarded-For header for client IP identification in web servers like Apache or Nginx. <br>
In a Forward Proxy, you have the ability to modify the X-Forwarded-For header to include arbitrary changes before forwarding it. <br>
Since the proxy connection request IP may differ from the actual client IP, it's recommended not to use this feature.<br>

[ Check Item ]
- Check if the "follow_x_forwarded_for" feature is restricted. If it's not explicitly specified in the configuration, it is in its default state (not restricted).
```bash
[root@localhost ~]# vim /etc/squid/squid.conf
...

follow_x_forwarded_for ...
follow_x_forwarded_for ...
```

[ Solution ]
- To restrict the "follow_x_forwarded_for" setting, limit it to the local host.
```bash
[root@localhost ~]# vim /etc/squid/squid.conf
...

follow_x_forwarded_for allow localhost   # <== Add
follow_x_forwarded_for deny all          # <== Add
request_header_access X-Forwarded-For deny all # <=== Add
```
- This configuration ensures that the "follow_x_forwarded_for" setting only allows the localhost to modify the X-Forwarded-For header and denies all other clients from modifying it.
  

## 7. Ensure Outbound X-Forwarded-For Header is restricted
The "forwarded_for" feature allows you to add the client's actual IP address to the HTTP request header for transmission.<br>

If the forwarded_for feature is enabled, the proxy server adds the client's IP address to the X-Forwarded-For header when making requests to external URLs.<br>
For example, when system A connects to www.google.com through a proxy, the proxy server sends the web page request to www.google.com with system A's IP address set in the X-Forwarded-For header. <br>

Since the internal system's IP is being sent to external hosts and can be identified, it's recommended not to use this feature.

[ Check Item ]
- Check if the forwarded_for feature is disabled. If it's not explicitly specified in the configuration, it is in its default state (enabled).
```bash
[root@localhost ~]# vim /etc/squid/squid.conf
...

forwarded_for delete  # <== It should be set to 'delete' or 'off'
```

[ Solution ]
- Set the "forwarded_for" to "delete" to disable the feature.
- To prevent clients from inserting IP addresses into the X-Forwarded-For header, block it using request_header_access.
```bash
[root@localhost ~]# vim /etc/squid/squid.conf
...

forwarded_for delete  # <== Add
request_header_access X-Forwarded-For deny all # <=== Add
```


## 8. Ensure HTTP Method is restricted
Configuring HTTP methods in Squid is the process of setting the allowed HTTP methods for URLs accessed through the proxy. <br>
Typically, only GET, POST, OPTIONS, and CONNECT should be allowed. <br>

The CONNECT method is used to establish a tunnel through the proxy and is commonly used for HTTPS connections.

[ Solution ]
- Set the allowed HTTP methods for proxy access. If not explicitly specified, all HTTP methods are allowed.
- For a "Forward Proxy", restrict the allowed methods to GET, POST, OPTIONS, and CONNECT.
```bash
[root@localhost ~]# vim /etc/squid/squid.conf

acl Safe_ports port 80              # http
acl Safe_ports port 443             # https
...

acl Safe_methods method GET POST OPTIONS CONNECT  # <== Define allowed methods
```
- This configuration ensures that only the specified HTTP methods (GET, POST, OPTIONS, and CONNECT) are allowed through the proxy, enhancing security.

  
## 9. Ensure Access Control Policy (ACL) is correct
Access control policies can vary depending on the implementation approach. <br>

If there are trusted internal hosts, domains, or IP ranges, you can configure the proxy to allow access to all external URLs. <br>

Alternatively, you can restrict access to specific external URLs only for trusted internal hosts, domains, or IP ranges. <br>

Each policy can also be controlled by setting a time limit for operation

[ Solution ]
- Package updates, library downloads, and other trusted targets (URLs) can be allowed for common usage.
- For other cases, configure access control policies by specifying trusted (source) hosts, domains, or IP ranges and specifying the necessary (destination) external URLs to restrict access.
- If proxy usage is required for a specific time period, set the operational hours using the time directive.

Here are some example scenarios of access control policies:)

### 9.1. Allow all external access for specific (source) hosts/ranges (Any destination). 
< squid.conf >
```bash
...

acl Safe_ports port 80              # http
acl Safe_ports port 443             # https
...

acl Safe_methods method GET POST OPTIONS CONNECT
...

acl service-src src "/etc/squid/acl/infra-src.acl"
acl service-dst dst all
...

http_access deny !Safe_ports
...

http_access allow Safe_methods service-src service-dst
http_access deny service-src

# And finally deny all other access to this proxy
http_access deny all
 
 
# Squid normally listens to port 3128
http_port 3128
```
< infra-src.acl >
```bash
192.168.100.22
live-oauth-app1
live-oauth-app2
pg-sec-logstore01.wadiz.office
www.mydomain.net    #Domain
.google.com         #Depth Domain
```

### 9.2. Allow specific (source) hosts/ranges to access specified (destination) URLs (Scenario 1).
< squid.conf >
```bash
...

acl Safe_ports port 80              # http
acl Safe_ports port 443             # https
...

acl Safe_methods method GET POST OPTIONS CONNECT
...

acl service-src src "/etc/squid/acl/infra-src.acl"
acl service-dst dstdomain "/etc/squid/acl/infra-dst.acl"
...

http_access deny !Safe_ports

...
http_access allow Safe_methods service-src service-dst
http_access allow localhost
http_access deny service-src

# And finally deny all other access to this proxy
http_access deny all
 
# Squid normally listens to port 3128
http_port 3128
```
< infra-src.acl >
```bash
10.10.1000/24      # public zone
192.168.100.0/24   # dev zone
192.168.101.0/24   # public rc
...
```
< infra-dst.acl >
```bash
.okta.com
rpm.releases.hashicorp.com
download.docker.com
.github.com
files.pythonhosted.org
api.slack.com
```

### 9.3. Allow specific (source) hosts/ranges to access specified (destination) URLs (Scenario 2).
< squid.conf >
```bash
...

acl Safe_ports port 80              # http
acl Safe_ports port 443             # https
...

acl Safe_methods method GET POST OPTIONS CONNECT
...

include /etc/squid/conf.d/object_src.conf
include /etc/squid/conf.d/object_dst.conf
include /etc/squid/conf.d/access_policy.conf
...

http_access deny Safe_methods !Safe_ports

...

# And finally deny all other access to this proxy
http_access allow localhost
http_access deny all
 
 
# Squid normally listens to port 3128
http_port 3128
```
< object_src.conf >
```bash
acl ip_all src 10.0.0.0/24          # office 
acl ip_all src 192.168.0.0/24       # office 
acl sandbox-webapp01 src 192.168.100.20
```
< object_dst.conf >
```bash
# dom_linux_mirror
acl dom_linux_mirror dstdomain mirrors.fedoraproject.org        # EPEL
acl dom_linux_mirror dstdomain vault.centos.org                 # CentOS 6
acl dom_linux_mirror dstdomain mirrors.rockylinux.org           # Rocky 8~9
acl dom_linux_mirror dstdomain mirror.anigil.com                # CentOS 6~7, Rocky 8~9, Ubuntu
acl dom_linux_mirror dstdomain dl.rockylinux.org                # Rocky Mirror

acl dom_python dstdomain pypi.python.org
acl dom_python dstdomain pypi.org
acl dom_python dstdomain files.pythonhosted.org

acl dom_slack dstdomain slack.com
acl dom_slack dstdomain api.slack.com
acl dom_slack dstdomain hooks.slack.com

```
< access_policy.conf > 
```bash
http_access allow Safe_methods ip_all dom_linux_mirror
http_access allow Safe_methods sandbox-webapp01 dom_slack
http_access allow Safe_methods sandbox-webapp01 dom_python
```

### 9.4. Configure policies with specified operating hours.
- policy set to work only from 00:00-19:00 every day
  
```bash
acl all_weekdays time 00:00-19:00
...

http_access allow Safe_methods all_weekdays service-src service-dst
http_access allow localhost
http_access deny service-src
```

- policy set to work on Saturday and Sunday only
  
```bash
acl weekend time S Su 00:00-23:59
...

http_access allow Safe_methods weekend service-src service-dst
http_access allow localhost
http_access deny service-src
```
 

## 10. Ensure detailed logging is enabled
In the Squid proxy access logs, the timestamp is recorded in Unix timestamp format, which is not human-readable.<br>
To improve log readability, you should convert the timestamp into a human-readable format, and the log's timezone should be set to the local system timezone. <br>

Additionally, access logs should include essential information for access log analysis, such as remote IP, requested URL, User-Agent, response status, data transfer size (bytes sent and received), and more.

[ Check Item ]
- Check if the proxy logs are currently stored in the default format.
```bash
[root@localhost ~]# tail -f /var/log/squid/access.log
1694992833.804     17 192.168.130.229 TCP_MISS/200 4814 GET http://mirror.anigil.com/rocky/8/BaseOS/x86_64/os/repodata/repomd.xml - HIER_DIRECT/123.215.145.59 text/xml
1694992833.907     87 192.168.130.229 TCP_REFRESH_UNMODIFIED/200 299272 GET http://mirror.anigil.com/rocky/8/BaseOS/x86_64/os/repodata/dae7e104812099a2f632ea4c5ef2769aca18ca1205abdd2c3ba6d171e319df3d-comps-BaseOS.x86_64.xml - HIER_DIRECT/123.215.145.59 text/xml
1694992833.979     68 192.168.130.229 TCP_REFRESH_UNMODIFIED/200 180225 GET http://mirror.anigil.com/rocky/8/BaseOS/x86_64/os/repodata/6e06094b5adbf763f3fb52604759f8ebcdc553db9dc920c9b30b61a65754dca7-updateinfo.xml.gz - HIER_DIRECT/123.215.145.59 application/octet-stream
1694992834.185    370 192.168.130.229 TCP_REFRESH_UNMODIFIED/200 2669167 GET http://mirror.anigil.com/rocky/8/BaseOS/x86_64/os/repodata/56d8b0ff58f5b55a73b424d817141f9f3e010b5554988993ba82a7143b0282b8-filelists.xml.gz - HIER_DIRECT/123.215.145.59 application/octet-stream
1694992834.191    380 192.168.130.229 TCP_REFRESH_UNMODIFIED/200 3141032 GET http://mirror.anigil.com/rocky/8/BaseOS/x86_64/os/repodata/f39a0bb438dd2cec4fecba48a4947d9bb0c2726a5ab4c5525e5d41817c7c436e-primary.xml.gz - HIER_DIRECT/123.215.145.59 application/octet-stream
1694992840.818     45 192.168.130.229 TCP_MISS/200 3538 GET http://mirror.anigil.com/rocky/8/extras/x86_64/os/repodata/repomd.xml - HIER_DIRECT/123.215.145.59 text/xml
1694992846.285      3 192.168.130.229 TCP_DENIED/403 3951 CONNECT rpm.dl.getenvoy.io:443 - HIER_NONE/- text/html
1694992846.296      3 192.168.130.229 TCP_DENIED/403 3951 CONNECT rpm.dl.getenvoy.io:443 - HIER_NONE/- text/html
1694992846.309      4 192.168.130.229 TCP_DENIED/403 3951 CONNECT rpm.dl.getenvoy.io:443 - HIER_NONE/- text/html
```

[ Solution ]
- change the timestamps to human-readable format
- set the timezone to the local system timezone
- Set the remote IP, requested URL, User-Agent, transfer result, and sent/received data size in the log format
```bash
[root@localhost ~]# vim /etc/squid/squid.conf
...

logformat custom_log %{%Y-%m-%d %H:%M:%S}tl %>a:%>p %Ss/%03>Hs:%Sh "%rm %ru HTTP/%rv" %mt %>Hs %<st %tr "%{User-Agent}>h" "%{Referer}>h"
access_log /var/log/squid/access.log custom_log
```
- This configuration changes the log format to a human-readable format and includes the desired information. For example:
```bash
[root@localhost ~]# cat /var/log/squid/access.log
...

2023-10-31 08:44:22 192.168.0.182:48834 NONE/000:HIER_NONE "NONE error:transaction-end-before-headers HTTP/0.0" - 0 0 0 "-" "-"
2023-10-31 08:45:22 192.168.0.182:45606 NONE/000:HIER_NONE "NONE error:transaction-end-before-headers HTTP/0.0" - 0 0 0 "-" "-"
2023-10-31 08:46:22 192.168.0.182:55104 NONE/000:HIER_NONE "NONE error:transaction-end-before-headers HTTP/0.0" - 0 0 0 "-" "-"
2023-10-31 08:46:32 192.168.0.149:53972 TCP_MISS/200:HIER_DIRECT "GET http://dl.rockylinux.org/pub/rocky/8/AppStream/x86_64/os/repodata/repomd.xml HTTP/1.1" text/xml 200 5265 6665 "libdnf (Rocky Linux 8.8; generic; Linux.x86_64)" "-"
2023-10-31 08:46:37 192.168.0.149:49404 TCP_MISS/200:HIER_DIRECT "GET http://dl.rockylinux.org/pub/rocky/8/BaseOS/x86_64/os/repodata/repomd.xml HTTP/1.1" text/xml 200 4793 234 "libdnf (Rocky Linux 8.8; generic; Linux.x86_64)" "-"
2023-10-31 08:46:42 192.168.0.149:49420 TCP_MISS/200:HIER_DIRECT "GET http://dl.rockylinux.org/pub/rocky/8/extras/x86_64/os/repodata/repomd.xml HTTP/1.1" text/xml 200 3517 233 "libdnf (Rocky Linux 8.8; generic; Linux.x86_64)" "-"
2023-10-31 08:46:42 192.168.130.225:40470 TCP_TUNNEL/200:HIER_DIRECT "CONNECT plugins.nessus.org:443 HTTP/1.1" - 200 5710 5674 "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36" "-"
2023-10-31 08:46:52 192.168.0.149:49432 TCP_TUNNEL/200:HIER_DIRECT "CONNECT mirror.kakao.com:443 HTTP/1.1" - 200 9445 10393 "libdnf (Rocky Linux 8.8; generic; Linux.x86_64)" "-"
2023-10-31 08:47:22 192.168.0.182:54734 NONE/000:HIER_NONE "NONE error:transaction-end-before-headers HTTP/0.0" - 0 0 0 "-" "-"
2023-10-31 08:48:22 192.168.0.182:40026 NONE/000:HIER_NONE "NONE error:transaction-end-before-headers HTTP/0.0" - 0 0 0 "-" "-"
2023-10-31 08:48:58 192.168.2.109:39028 TCP_MISS/200:HIER_DIRECT "GET http://dl.rockylinux.org/pub/rocky/8/AppStream/x86_64/os/repodata/repomd.xml HTTP/1.1" text/xml 200 5264 5428 "libdnf (Rocky Linux 8.8; generic; Linux.x86_64)" "-"
2023-10-31 08:48:58 192.168.2.109:39038 TCP_MISS/200:HIER_DIRECT "GET http://dl.rockylinux.org/pub/rocky/8/BaseOS/x86_64/os/repodata/repomd.xml HTTP/1.1" text/xml 200 4791 236 "libdnf (Rocky Linux 8.8; generic; Linux.x86_64)" "-"
2023-10-31 08:48:58 192.168.2.109:39044 TCP_MISS/200:HIER_DIRECT "GET http://dl.rockylinux.org/pub/rocky/8/extras/x86_64/os/repodata/repomd.xml HTTP/1.1" text/xml 200 3515 232 "libdnf (Rocky Linux 8.8; generic; Linux.x86_64)" "-"
2023-10-31 08:49:04 192.168.2.109:55508 TCP_TUNNEL/200:HIER_DIRECT "CONNECT mirror.kakao.com:443 HTTP/1.1" - 200 9442 63 "libdnf (Rocky Linux 8.8; generic; Linux.x86_64)" "-"
```
- The timestamp is now in the format "YYYY-MM-DD HH:MM:SS," which is much more readable.

## 11. Ensure log files are rotated
Logs should be managed on a daily basis and stored for more than 30 days. For cache logs, you can set the retention period as needed.

[ Logs to be retained ]

ID | Value  | File | Description
----- | ----- | ----- | -----
1 | Access Logs | /var/log/squid/access.log | Records information about HTTP requests and responses processed by the proxy.
2 | Cache Logs | /var/log/squid/cache.log | Contains information about the operation of the proxy server. It is used for Squid debugging, performance monitoring, and troubleshooting.

[ Solution ]
- use logrotate to automatically manage and retain logs as specified. Below is an example logrotate configuration for Squid logs:
```bash
[root@localhost ~]# vim /etc/logrotate.d/squid
...

/var/log/squid/*.log {
    daily
    rotate 30
    compress
    notifempty
    missingok
    nocreate
    dateext
    sharedscripts
    postrotate
      # Ask Squid to reopen its logs. (logfile_rotate 0 is set in squid.conf)
      # Errors are redirected to make it silent if Squid is not running
      /usr/sbin/squid -k rotate 2>/dev/null
      # Wait a little to allow Squid to catch up before the logs are compressed
      sleep 1
    endscript
}
```
- Logs files after logrotate
```bash
[root@localhost ~]# ls -al /var/log/squid
total 342364
drwxrwx---.  2 squid root      4096 Oct 31 03:08 .
drwxr-xr-x. 13 root  root      4096 Oct 29 03:21 ..
-rw-r-----.  1 squid squid    94241 Oct 31 10:22 access.log
-rw-r-----.  1 squid squid      153 Oct 23 13:48 access.log-20231023.gz
-rw-r-----.  1 squid squid    17695 Oct 24 03:37 access.log-20231024.gz
-rw-r-----.  1 squid squid    28262 Oct 25 03:05 access.log-20231025.gz
-rw-r-----.  1 squid squid    24459 Oct 26 03:45 access.log-20231026.gz
-rw-r-----.  1 squid squid    23465 Oct 27 03:47 access.log-20231027.gz
-rw-r-----.  1 squid squid    24322 Oct 28 03:37 access.log-20231028.gz
-rw-r-----.  1 squid squid    22576 Oct 29 03:20 access.log-20231029.gz
-rw-r-----.  1 squid squid    22012 Oct 30 03:18 access.log-20231030.gz
-rw-r-----.  1 squid squid    29883 Oct 31 03:07 access.log-20231031.gz
...
```

***
  

## Tips 1:  completed squid.conf 
< squid.conf >
```bash
acl Safe_ports port 80              # http
acl Safe_ports port 443             # https

# Method Setting
acl Safe_methods method GET POST OPTIONS CONNECT # HTTP request method [fast]

#
# ACL For Server
#
# ec2 server 
acl ec2-server-src src "/etc/squid/acl/ec2-servers-src.acl"
# ec2 server outbound URL
acl ec2-server-dst dstdomain "/etc/squid/acl/ec2-servers-dst-commons.acl"
# Linux dnf/yum linux pkg update manager
acl pkg-update-user-agent browser -i libdnf yum


# Deny requests to certain unsafe ports
http_access deny !Safe_ports

# Only allow cachemgr access from localhost
http_access allow localhost


#
# HTTP Access Policy
#

# ACL outbound Server Common URLs
http_access allow Safe_methods ec2-server-src ec2-server-dst
# ACL outbound Server Linux pkg-Updates
http_access allow Safe_methods ec2-server-src pkg-update-user-agent


# And finally deny all other access to this proxy
http_access deny all

# Squid normally listens to port 3128
http_port 3128

#
# Uncomment and adjust the following to add a disk cache directory.
#
cache_dir ufs /var/spool/squid 50000 16 256

# Leave coredumps in the first cache dir
coredump_dir /var/spool/squid

#
# Add any of your own refresh_pattern entries above these.
#
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320

#
# Log Format
#
logformat custom_log %{%Y-%m-%d %H:%M:%S}tl %>a:%>p %Ss/%03>Hs:%Sh "%rm %ru HTTP/%rv" %mt %>Hs %<st %tr "%{User-Agent}>h" "%{Referer}>h"
access_log /var/log/squid/access.log custom_log

#
# Security Configuration
#

httpd_suppress_version_string on
via off
forwarded_for delete
follow_x_forwarded_for deny all
request_header_access X-Forwarded-For deny all
reply_header_access X-Cache deny all
reply_header_access X-Cache-Lookup deny all
reply_header_access Server deny all
```

## Tips 2: Very simple proxying for Linux yum package updates
When performing Linux yum or dnf package updates through a Squid proxy, it is often necessary to specify all the URLs that yum or dnf may access, which can be a cumbersome and error-prone task.<br><br>
However, you can take advantage of the User-Agent information provided by these package managers to simplify the access control configuration in Squid. <br>

Here's how you can do it:

[ Solution ]
- In your squid.conf configuration file, define an access control list (ACL) for dnf/yum Linux package update managers based on the User-Agent:
  
< squid.conf >
```bash

# ACL for dnf/yum linux pkg update manager
acl pkg-update-user-agent browser -i libdnf yum

# ACL outbound Server Linux pkg-Updates
http_access allow Safe_methods avd-server-src pkg-update-user-agent
```

This configuration ensures that Squid allows access to URLs requested by package managers based on their User-Agent information, eliminating the need to explicitly manage URL lists.


This approach simplifies the configuration and ensures that requests from package managers such as yum and dnf are correctly routed through the proxy.


Here's an example of the Squid access log showing this configuration in action:
```
# cat /var/log/squid/access.log
...

2023-11-03 14:57:04 10.10.120.10:54326 NONE/503:HIER_NONE "CONNECT mirrors.rockylinux.org:443 HTTP/1.1" - 503 0 0 "libdnf (Rocky Linux 8.8; generic; Linux.x86_64)" "-"
2023-11-03 14:57:04 10.10.120.10:54334 NONE/503:HIER_NONE "CONNECT mirrors.rockylinux.org:443 HTTP/1.1" - 503 0 0 "libdnf (Rocky Linux 8.8; generic; Linux.x86_64)" "-"
2023-11-03 14:57:04 10.10.120.10:54346 NONE/503:HIER_NONE "CONNECT mirrors.rockylinux.org:443 HTTP/1.1" - 503 0 0 "libdnf (Rocky Linux 8.8; generic; Linux.x86_64)" "-"
...
2023-11-03 16:02:03 10.100.120.11:43496 TCP_MISS/200:HIER_DIRECT "GET http://nginx.org/packages/centos/7/x86_64/repodata/4395bce9c52aa8a4cc475e180bcce2399c8a4d720b16ce726d6fded994a7f89b-primary.sqlite.bz2 HTTP/1.1" application/octet-stream 200 88823 709 "urlgrabber/3.10 yum/3.4.3" "-"
2023-11-03 16:02:09 10.100.120.11:43508 TCP_HIT/200:HIER_NONE "GET http://nginx.org/packages/centos/7/x86_64/RPMS/nginx-1.24.0-1.el7.ngx.x86_64.rpm HTTP/1.1" application/x-redhat-package-manager 200 823278 2 "urlgrabber/3.10 yum/3.4.3" "-"

```

# And...
- If you find this helpful, please the **"star"**:star2: to support further improvements.
