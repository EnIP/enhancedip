echo off

set PATH=%PATH%;C:\Program Files\Oracle\VirtualBox\

call :printbanner
call :pauseloop 3
echo "0) Starting to unpack."

REM ############################
REM #
REM # CLONE N2 to other VMs
REM #
REM ############################
VBoxManage.exe clonevm IMPORT-N2 --name IMPORT-N1 --register
VBoxManage.exe clonevm IMPORT-N2 --name IMPORT-EIP1 --register
VBoxManage.exe clonevm IMPORT-N2 --name IMPORT-EIP2 --register
echo "Step 1) VM Cloning done."

REM ##################################
REM #
REM # SETUP NETWORK CARDS ON NEW VMS
REM #
REM ##################################
VBoxManage.exe modifyvm IMPORT-N1 --nic2 intnet
VBoxManage.exe modifyvm IMPORT-N1 --intnet2 intnet1
VBoxManage.exe modifyvm IMPORT-N1 --nic3 none

VBoxManage.exe modifyvm IMPORT-EIP1 --nic1 intnet
VBoxManage.exe modifyvm IMPORT-EIP1 --intnet1 intnet1
VBoxManage.exe modifyvm IMPORT-EIP1 --nic2 none
VBoxManage.exe modifyvm IMPORT-EIP1 --nic3 none

VBoxManage.exe modifyvm IMPORT-EIP2 --nic1 intnet
VBoxManage.exe modifyvm IMPORT-EIP2 --intnet1 intnet2
VBoxManage.exe modifyvm IMPORT-EIP2 --nic2 none
VBoxManage.exe modifyvm IMPORT-EIP2 --nic3 none
echo "Step 2) VM networking setup done."


REM ####################################################
REM #
REM # start the VMs
REM #
REM ####################################################
VBoxManage startvm IMPORT-N2
VBoxManage startvm IMPORT-N1
VBoxManage startvm IMPORT-EIP1
VBoxManage startvm IMPORT-EIP2
echo "Step 3) VMs starting.  Script will continue in 4 minutes."
call :pauseloop 250

REM ####################################################
REM #
REM # run a command on each guest to get the guest setup
REM #
REM ####################################################
SET ENIPDIR=/home/user/enhancedip-config

VBoxManage guestcontrol IMPORT-N2 exec --image %ENIPDIR%/N2.sh --username user --password password
VBoxManage guestcontrol IMPORT-N1 exec --image %ENIPDIR%/N1.sh --username user --password password
VBoxManage guestcontrol IMPORT-EIP1 exec --image %ENIPDIR%/EIP1.sh --username user --password password
VBoxManage guestcontrol IMPORT-EIP2 exec --image %ENIPDIR%/EIP2.sh --username user --password password
echo "Step 4) Completed execution of setup scripts."
pause
exit

:printbanner
echo ''
echo ''
echo ""!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "This script is going to take a long time to run!!!"
echo "Please don't interrupt/stop it in the middle of processing!"
echo ""!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo ''
echo ''
echo ''
echo ''
pause
GOTO:EOF

REM The only way to pause the script
:pauseloop
@ping 127.0.0.1 -n %1 -w 1000 > nul
GOTO:EOF