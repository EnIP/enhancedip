#!/bin/sh

#ip forwarding on
echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -F 
iptables -F -t nat

#NAT IPv4 out eth0
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

#load Enhanced IP NAT driver
insmod /root/enhancedip-code/kernel/eipnat/eipnat.ko masq_ip="2.2.2.2"
#insmod /root/enhancedip/kernel/0.0.8/eipnat/eipnat.ko masq_ip="2.2.2.2"
#insmod /root/enhancedip/kernel/0.0.7/eipnat/eipnat.ko masq_ip="65.127.220.142"

#port 8080 to 10.3.3.2:80
#iptables -t nat -A PREROUTING -m tcp -p tcp -i eth0 -d 2.2.2.2 --dport 8080 --sport 1024:65535 -j DNAT --to 10.3.3.2:80
#iptables -A FORWARD -m tcp -p tcp -i eth0 -o eth1 -d 10.3.3.2 --dport 80 --sport 1024:65535 -m state --state NEW -j ACCEPT

#port 2222 to 10.3.3.2:22
#iptables -t nat -A PREROUTING -m tcp -p tcp -i eth0 -d 2.2.2.2 --dport 2222 --sport 1024:65535 -j DNAT --to 10.3.3.2:22
#iptables -A FORWARD -m tcp -p tcp -i eth0 -o eth1 -d 10.3.3.2 --dport 22 --sport 1024:65535 -m state --state NEW -j ACCEPT

#masquerade all outbound on eth0
#iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE


