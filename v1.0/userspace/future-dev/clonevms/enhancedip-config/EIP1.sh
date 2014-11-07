#!/bin/sh


echo password | sudo -S hostname eip1
echo password | sudo sh -c "echo 'eip1' > /etc/hostname"

echo password | sudo -S cp EIP1-interfaces /etc/network/interfaces

echo password | sudo -S cp rc.local.empty /etc/rc.local

echo password | sudo -S rm -f /etc/udev/rules.d/70-persistent-net.rules
echo password | sudo -S /etc/init.d/networking restart

echo password | sudo -S reboot



