#!/bin/sh


echo password | sudo -S hostname n1
echo password | sudo sh -c "echo 'n1' > /etc/hostname"

echo password | sudo -S cp N1-interfaces /etc/network/interfaces

echo password | sudo -S cp rc.local.N1 /etc/rc.local

echo password | sudo -S rm -f /etc/udev/rules.d/70-persistent-net.rules
echo password | sudo -S /etc/init.d/networking restart

echo password | sudo -S reboot


