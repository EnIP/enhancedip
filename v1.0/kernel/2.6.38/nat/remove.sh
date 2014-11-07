iptables -F -t nat

rmmod ipt_MASQUERADE
rmmod iptable_nat
rmmod nf_nat


