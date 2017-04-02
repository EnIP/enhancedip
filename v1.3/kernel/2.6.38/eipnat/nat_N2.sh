#!/bin/sh

MASQ_IP="2.2.2.2"
NIC_NAME="eth0"

############################################
#
# NO EDITS BELOW HERE
#
#

#ip forwarding on
echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -F 
iptables -F -t nat

#NAT IPv4 out eth0
iptables -t nat -A POSTROUTING -d 2.2.2.0/24 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -o eth2 -j MASQUERADE

#load Enhanced IP NAT driver
insmod /root/enhancedip-code/kernel/2.6.38/eipnat/eipnat.ko masq_ip=$MASQ_IP nic_name=$NIC_NAME


