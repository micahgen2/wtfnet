"""Real-looking command output from each OS, saved as strings for the tests."""

PING_LINUX_OK = """PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=11.2 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=10.9 ms
64 bytes from 1.1.1.1: icmp_seq=3 ttl=57 time=12.0 ms
64 bytes from 1.1.1.1: icmp_seq=4 ttl=57 time=11.1 ms

--- 1.1.1.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 10.9/11.3/12.0/0.4 ms
"""

PING_LINUX_LOSSY = """PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=3.2 ms
64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=4.1 ms

--- 192.168.1.1 ping statistics ---
4 packets transmitted, 2 received, 50% packet loss, time 3050ms
rtt min/avg/max/mdev = 3.2/3.6/4.1/0.5 ms
"""

PING_LINUX_DEAD = """PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.

--- 8.8.8.8 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3070ms
"""

PING_LINUX_UNRESOLVED = "ping: nosuchhost.invalid: Name or service not known\n"

PING_MAC_OK = """PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=11.234 ms
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=10.901 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=12.012 ms
64 bytes from 1.1.1.1: icmp_seq=3 ttl=57 time=11.100 ms

--- 1.1.1.1 ping statistics ---
4 packets transmitted, 4 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 10.901/11.312/12.012/0.431 ms
"""

PING_WIN_OK = """
Pinging 1.1.1.1 with 32 bytes of data:
Reply from 1.1.1.1: bytes=32 time=11ms TTL=57
Reply from 1.1.1.1: bytes=32 time=10ms TTL=57
Reply from 1.1.1.1: bytes=32 time=12ms TTL=57
Reply from 1.1.1.1: bytes=32 time=11ms TTL=57

Ping statistics for 1.1.1.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 10ms, Maximum = 12ms, Average = 11ms
"""

# Windows quirk: "Destination host unreachable" is counted as Received.
PING_WIN_UNREACHABLE = """
Pinging 192.168.1.1 with 32 bytes of data:
Reply from 192.168.1.23: Destination host unreachable.
Reply from 192.168.1.23: Destination host unreachable.
Reply from 192.168.1.23: Destination host unreachable.
Reply from 192.168.1.23: Destination host unreachable.

Ping statistics for 192.168.1.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
"""

GATEWAY_LINUX = "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n"
GATEWAY_MAC = """   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
"""
GATEWAY_WIN = """IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      10.0.0.1      10.0.0.5     50
          0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.23 25
===========================================================================
"""
GATEWAY_NETSTAT = """Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
0.0.0.0         192.168.1.1     0.0.0.0         UG        0 0          0 eth0
192.168.1.0     0.0.0.0         255.255.255.0   U         0 0          0 eth0
"""

IFACES_IP = """1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: wlan0    inet 192.168.1.23/24 brd 192.168.1.255 scope global dynamic wlan0\\       valid_lft 86000sec
"""
IFACES_IP_LINKLOCAL = "2: eth0    inet 169.254.77.12/16 brd 169.254.255.255 scope link eth0\\\n"
IFACES_IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether aa:bb:cc:dd:ee:ff
\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x6
\tinet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
"""
IFACES_IPCONFIG = """Windows IP Configuration

   Host Name . . . . . . . . . . . . : DESKTOP-ABC

Ethernet adapter Ethernet:

   Media State . . . . . . . . . . . : Media disconnected

Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . : lan
   IPv4 Address. . . . . . . . . . . : 192.168.1.23(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
"""

NSLOOKUP_UNIX_OK = """Server:\t\t1.1.1.1
Address:\t1.1.1.1#53

Non-authoritative answer:
Name:\texample.com
Address: 93.184.216.34
"""
NSLOOKUP_WIN_OK = """Server:  UnKnown
Address:  192.168.1.1

Non-authoritative answer:
Name:    example.com
Addresses:  2606:2800:220:1:248:1893:25c8:1946
          93.184.216.34

"""
NSLOOKUP_NXDOMAIN = """Server:\t\t1.1.1.1
Address:\t1.1.1.1#53

** server can't find nosuchhost.invalid: NXDOMAIN
"""
NSLOOKUP_TIMEOUT = ";; connection timed out; no servers could be reached\n"

TRACE_UNIX_REACHED = """traceroute to example.com (93.184.216.34), 20 hops max, 60 byte packets
 1  192.168.1.1  1.234 ms  1.100 ms
 2  10.20.0.1  8.5 ms  8.9 ms
 3  * *
 4  93.184.216.34  21.0 ms  20.8 ms
"""
TRACE_UNIX_STALLED = """traceroute to example.com (93.184.216.34), 20 hops max, 60 byte packets
 1  192.168.1.1  1.234 ms  1.100 ms
 2  10.20.0.1  8.5 ms  8.9 ms
 3  * *
 4  * *
 5  * *
"""
TRACE_WIN_REACHED = """
Tracing route to example.com [93.184.216.34]
over a maximum of 20 hops:

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     9 ms     8 ms     9 ms  10.20.0.1
  3     *        *        *     Request timed out.
  4    21 ms    20 ms    21 ms  93.184.216.34

Trace complete.
"""


# ------------------------------------------------------------------- IPv6
IFACES_IP_V6 = """1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
1: lo    inet6 ::1/128 scope host \\       valid_lft forever preferred_lft forever
2: wlan0    inet 192.168.1.23/24 brd 192.168.1.255 scope global dynamic wlan0\\       valid_lft 86000sec
2: wlan0    inet6 2607:f8b0:4005:80a::2003/64 scope global dynamic mngtmpaddr \\       valid_lft 86000sec
2: wlan0    inet6 fe80::1c2b:3d4e:5f60:7182/64 scope link \\       valid_lft forever preferred_lft forever
"""
# Link-local and a private fd00:: ULA only: IPv6 exists on the LAN but not the internet.
IFACES_IP_V6_LOCAL_ONLY = """2: wlan0    inet 192.168.1.23/24 brd 192.168.1.255 scope global wlan0\\
2: wlan0    inet6 fd12:3456:789a::5/64 scope global wlan0\\
2: wlan0    inet6 fe80::1c2b:3d4e:5f60:7182/64 scope link \\
"""
IFACES_IFCONFIG_V6 = IFACES_IFCONFIG + """\tinet6 2607:f8b0:4005:80a::2003 prefixlen 64 autoconf secured
\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x6
"""
IFACES_IPCONFIG_V6 = """Windows IP Configuration

Wireless LAN adapter Wi-Fi:

   IPv6 Address. . . . . . . . . . . : 2607:f8b0:4005:80a::2003
   Temporary IPv6 Address. . . . . . : 2607:f8b0:4005:80a:b1c2:d3e4:f506:1728
   Link-local IPv6 Address . . . . . : fe80::1c2b:3d4e:5f60:7182%12
   IPv4 Address. . . . . . . . . . . : 192.168.1.23(Preferred)
"""

GATEWAY6_LINUX = "default via fe80::1 dev wlan0 proto ra metric 1024 expires 1790sec hoplimit 64 pref medium\n"
GATEWAY6_MAC = """   route to: default
destination: default
       mask: default
    gateway: fe80::1%en0
  interface: en0
"""
GATEWAY6_WIN = """IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
  1    331 ::1/128                  On-link
 12    281 ::/0                     fe80::1
 12    281 2607:f8b0:4005:80a::/64  On-link
===========================================================================
"""
GATEWAY6_NETSTAT = """Kernel IPv6 routing table
Destination                    Next Hop                   Flag Met Ref Use If
::/0                           fe80::1                    UG   1024 0     0 wlan0
"""

PING6_LINUX_OK = """PING 2606:4700:4700::1111(2606:4700:4700::1111) 56 data bytes
64 bytes from 2606:4700:4700::1111: icmp_seq=1 ttl=57 time=14.2 ms
64 bytes from 2606:4700:4700::1111: icmp_seq=2 ttl=57 time=13.9 ms
64 bytes from 2606:4700:4700::1111: icmp_seq=3 ttl=57 time=15.0 ms
64 bytes from 2606:4700:4700::1111: icmp_seq=4 ttl=57 time=14.1 ms

--- 2606:4700:4700::1111 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 13.9/14.3/15.0/0.4 ms
"""
PING6_LINUX_DEAD = """PING 2606:4700:4700::1111(2606:4700:4700::1111) 56 data bytes

--- 2606:4700:4700::1111 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3070ms
"""
# macOS ping6 says "hlim=" instead of "ttl=" and spells it "std-dev".
PING6_MAC_OK = """PING6(56=40+8+8 bytes) 2607:f8b0::2003 --> 2606:4700:4700::1111
16 bytes from 2606:4700:4700::1111, icmp_seq=0 hlim=57 time=14.201 ms
16 bytes from 2606:4700:4700::1111, icmp_seq=1 hlim=57 time=13.900 ms
16 bytes from 2606:4700:4700::1111, icmp_seq=2 hlim=57 time=15.000 ms
16 bytes from 2606:4700:4700::1111, icmp_seq=3 hlim=57 time=14.100 ms

--- 2606:4700:4700::1111 ping6 statistics ---
4 packets transmitted, 4 packets received, 0.0% packet loss
round-trip min/avg/max/std-dev = 13.900/14.300/15.000/0.400 ms
"""
# Windows IPv6 replies have NO "TTL=" field.
PING6_WIN_OK = """
Pinging 2606:4700:4700::1111 with 32 bytes of data:
Reply from 2606:4700:4700::1111: time=14ms
Reply from 2606:4700:4700::1111: time=13ms
Reply from 2606:4700:4700::1111: time<1ms
Reply from 2606:4700:4700::1111: time=14ms

Ping statistics for 2606:4700:4700::1111:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 14ms, Average = 10ms
"""
PING6_WIN_UNREACHABLE = """
Pinging 2606:4700:4700::1111 with 32 bytes of data:
Reply from 2607:f8b0:4005:80a::2003: Destination host unreachable.
Reply from 2607:f8b0:4005:80a::2003: Destination host unreachable.

Ping statistics for 2606:4700:4700::1111:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
"""

NSLOOKUP_AAAA_OK = """Server:\t\t2606:4700:4700::1111
Address:\t2606:4700:4700::1111#53

Non-authoritative answer:
Name:\texample.com
Address: 2606:2800:21f:cb07:6820:80da:af6b:8b2c
"""
NSLOOKUP_AAAA_WIN = """Server:  one.one.one.one
Address:  2606:4700:4700::1111

Non-authoritative answer:
Name:    example.com
Addresses:  2606:2800:21f:cb07:6820:80da:af6b:8b2c
          2606:2800:220:1:248:1893:25c8:1946

"""
NSLOOKUP_AAAA_NONE = """Server:\t\t1.1.1.1
Address:\t1.1.1.1#53

Non-authoritative answer:

"""

TRACE6_UNIX_REACHED = """traceroute to example.com (2606:2800:21f:cb07:6820:80da:af6b:8b2c), 20 hops max, 80 byte packets
 1  fe80::1  1.9 ms  1.7 ms
 2  2607:f8b0:4005::1  9.1 ms  8.8 ms
 3  * *
 4  2606:2800:21f:cb07:6820:80da:af6b:8b2c  22.0 ms  21.5 ms
"""
# Same destination, but the header spells it out in full: must still count as reached.
TRACE6_UNIX_EXPANDED_HEADER = """traceroute to example.com (2606:2800:021f:cb07:6820:80da:af6b:8b2c), 20 hops max, 80 byte packets
 1  fe80::1  1.9 ms  1.7 ms
 2  2606:2800:21f:cb07:6820:80da:af6b:8b2c  22.0 ms  21.5 ms
"""
TRACE6_UNIX_STALLED = """traceroute to example.com (2606:2800:21f:cb07:6820:80da:af6b:8b2c), 20 hops max, 80 byte packets
 1  fe80::1  1.9 ms  1.7 ms
 2  * *
 3  * *
"""
TRACE6_WIN_REACHED = """
Tracing route to example.com [2606:2800:21f:cb07:6820:80da:af6b:8b2c]
over a maximum of 20 hops:

  1    <1 ms    <1 ms    <1 ms  fe80::1
  2     9 ms     8 ms     9 ms  2607:f8b0:4005::1
  3    22 ms    21 ms    22 ms  2606:2800:21f:cb07:6820:80da:af6b:8b2c

Trace complete.
"""

# Real macOS `nslookup -type=AAAA` output: no "Name:" line, "has AAAA address" instead.
NSLOOKUP_AAAA_MAC = """Server:\t\t2600:6c60:3ff0:c960::1
Address:\t2600:6c60:3ff0:c960::1#53

Non-authoritative answer:
google.com\thas AAAA address 2607:f8b0:4009:803::200e

Authoritative answers can be found from:

"""
NSLOOKUP_A_MAC_TYPED = """Server:\t\t1.1.1.1
Address:\t1.1.1.1#53

Non-authoritative answer:
google.com\thas address 142.250.80.46

Authoritative answers can be found from:
"""
