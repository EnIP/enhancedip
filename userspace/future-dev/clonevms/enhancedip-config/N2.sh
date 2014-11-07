#!/bin/sh


echo password | sudo -S hostname n2
echo password | sudo sh -c "echo 'n2' > /etc/hostname"
echo password | sudo reboot






