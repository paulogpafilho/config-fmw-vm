#!/bin/bash
#-------------------------------------------------------------
# Bash script to Configure a new OEL Basic Server
# This script is intended to configure OEL Server Versions 6.x
# Created by Paulo Albuquerque
# Email: paulogpafilho@gmail.com
# Creation Date: 11/10/12
# Last Revision: 20140403.01
# It depends on the following files that should be present in
# the same location this script is executed:
# dhcp.template, domain.template, hosts.template, 
# named.template, namedboot.template, network.template, 
# resolv.template, reverse.template, static.template
#-------------------------------------------------------------
export IFS="|"
#-------------------------------------------------------------
# Defining SHMMAX depeding on the total physical memory 
# available, according to Support Note 567506.1, recommended 
# value should be 1(one) byte less than Total Physical Memory 
# available
#-------------------------------------------------------------
MEM_KB=`grep MemTotal /proc/meminfo | awk '{print $2}'`
let "MEM_BYTE=$MEM_KB * 1024"
let "SHMMAX=$MEM_BYTE - 1"

#-------------------------------------------------------------
# Global Variables, used by the script to configure the system.
# Define here your preferences, the defaults here should fit
# most of the cases.
#-------------------------------------------------------------
FMW_USER_NAME="oracle"
FMW_USER_PASSWORD="Oracle123"
ORACLE_INSTALL_GROUP="oinstall"
ORACLE_DBA_INSTALL_GROUP="dba"
BASE_SHARED_STORE="/u01"
DOMAIN_NAME="mycompany.com"
DNS_SERVER_IP="192.168.56.200"
HOSTS="|192.168.56.200 thorium.mycompany.com thorium|192.168.56.201 promethium.mycompany.com promethium|192.168.56.202 beryllium.mycompany.com beryllium|192.168.56.203 uranium.mycompany.com uranium|192.168.56.204 tungsten.mycompany.com tungsten"


#-------------------------------------------------------------
# OS Constants - Usually there is no need to change the values 
# here unless your system has different paths for the config 
# files declared below
declare -r CREATION_DATE=`date +%Y%m%d-%H%M%S`
declare -r FSTAB_CONFIG_FILE="/etc/fstab"
declare -r NETWORK_CONFIG_FILE="/etc/sysconfig/network"
declare -r ETHERNET_CONFIG_FILE="/etc/sysconfig/network-scripts/ifcfg"
declare -r DNS_CONFIG_FILE="/etc/resolv.conf"
declare -r HOSTS_CONFIG_FILE="/etc/hosts"
declare -r SUDOERS_DIRECTORY="/etc/sudoers.d"
declare -r SSHD_CONFIG_FILE="/etc/ssh/sshd_config"
declare -r KERNEL_SYSCTL_FILE="/etc/sysctl.conf"
declare -r USER_LIMITS_FILE="/etc/security/limits.conf"
declare -r CDROM_FOLDER="/media/cdrom0"

#-------------------------------------------------------------
# OS Limits defined as per the last Enterprise Deployment Guide
# http://docs.oracle.com/cd/E40329_01/doc.1112/e48618/toc.htm
# Those can be changed if there is any special need.
#-------------------------------------------------------------
declare -r RECOM_SEMMSL=256
declare -r RECOM_SEMMNS=32000
declare -r RECOM_SEMOPM=100
declare -r RECOM_SEMMNI=142
declare -r RECOM_SHMALL=2097152
declare -r RECOM_SHMMAX=$SHMMAX
declare -r RECOM_SHMMNI=4096
declare -r RECOM_FILE_MAX=6815744
declare -r RECOM_IP_LOCAL_PORT_RANGE_MIN=9000
declare -r RECOM_IP_LOCAL_PORT_RANGE_MAX=65500
declare -r RECOM_RMEM_DEFAULT=262144
declare -r RECOM_RMEM_MAX=4194304
declare -r RECOM_WMEM_DEFAULT=262144
declare -r RECOM_WMEM_MAX=1048576
declare -r RECOM_AIO_MAX_NR=1048576
declare -r NOFILE_SOFT_LIMIT=4096
declare -r NOFILE_HARD_LIMIT=65536
declare -r NPROC_SOFT_LIMIT=2047
declare -r NPROC_HARD_LIMIT=16384
declare -r STACK_SOFT_LIMIT=10240
declare -r STACK_HARD_LIMIT=32768
#-------------------------------------------------------------
# Helper Variables to define OS limits.
# Attention: do not change those
#-------------------------------------------------------------
READ_SEMMSL=NULL
READ_SEMMNS=NULL
READ_SEMOPM=NULL
READ_SEMMNI=NULL
READ_SHMALL=NULL
READ_SHMMAX=NULL
READ_SHMMNI=NULL
READ_FILE_MAX=NULL
READ_IP_LOCAL_PORT_RANGE_MIN=NULL
READ_IP_LOCAL_PORT_RANGE_MAX=NULL
READ_RMEM_DEFAULT=NULL
READ_RMEM_MAX=NULL
READ_WMEM_DEFAULT=NULL
READ_WMEM_MAX=NULL
READ_AIO_MAX_NR=NULL


#-------------------------------------------------------------------
# Usage Function, explaining the scrip usage
#-------------------------------------------------------------------
function usage(){
    clear
    echo "This is a basic script that will configure an Oracle Enterprise Linux 6.3 running on Oracle VirtualBox"
    echo "It was created to help configure Virtual Machines for testing purposes, do not use it in live environments"
    echo "How to use this script:"
    echo ""
    echo "1 - Make sure you set this file permission to chmod u+rwx THIS_FILE"
    echo "2 - You have to run this script as root, or else you might get errors in some tasks"
    echo "3 - Before running ths script, review the Constants and Global Variables section to make sure paths and names match your Linux Installation."
}

#-------------------------------------------------------------------
# Backup Original Files
# It will back up the ethernet, etwork, dns and hosts configuration
# files to the location where this script is run
#-------------------------------------------------------------------
function backUpFiles(){
    echo "Backing up original Configuration Files"
    cp $ETHERNET_CONFIG_FILE-* .
    cp $NETWORK_CONFIG_FILE "./network.$CREATION_DATE"
    cp $DNS_CONFIG_FILE "./resolv.conf.$CREATION_DATE"
    cp $HOSTS_CONFIG_FILE "./hosts.$CREATION_DATE"
    cp $KERNEL_SYSCTL_FILE "./sysctl.conf.$CREATION_DATE"
    cp $USER_LIMITS_FILE "./limits.conf.$CREATION_DATE"
}

#-------------------------------------------------------------------
# Configure Network
#-------------------------------------------------------------------
function configureNetwork(){
    clear
    echo "-- Configure Network --"
    echo ""
    read -p 'Enter this machine Simple Name: ' SIMPLE_NAME
    #echo ""
    #read -p 'Enter this machine Domain (ie: mycompany.com): ' DOMAIN_NAME
    #echo ""
	#read -p 'Enter the IP of this domain DNS Server: ' DNS_SERVER_IP
	echo ""
    while true;
    do
        FULL_NAME="$SIMPLE_NAME.$DOMAIN_NAME"
        ETHERNET_CFG_FILE=""
		echo " - Interface Configuration - "
		echo ""
        read -p 'Choose the type of ip address configuration (dhcp/static): ' BOOT_PROT
        echo ""
        read -p 'Type in the device name (ie. eth0, eth1): ' DEVICE_NAME
        echo ""
        read -p 'Is this the default route network? - Recommended yes for dhcp. (yes/no) ' DEF_ROUTE
		
        ETHERNET_CFG_FILE="$ETHERNET_CONFIG_FILE-$DEVICE_NAME"
        HWADDR=`cat $ETHERNET_CFG_FILE | grep HWADDR`
        UUID=`cat $ETHERNET_CFG_FILE | grep UUID`
        echo ""
        if [ "$BOOT_PROT" == "dhcp" ]; then
		    # Save the dhcp configuration for this device
		    sed -e "s;%DEVICE_NAME%;$DEVICE_NAME;g" -e "s;%UUID%;$UUID;g" -e "s;%HWADDR%;$HWADDR;g" -e "s;%DEF_ROUTE%;$DEF_ROUTE;g" ./dhcp.template > $ETHERNET_CFG_FILE
        else
            read -p 'Enter the IP Address for this device: ' IP_ADDRESS
            echo ""
            read -p 'Enter the Gateway for this device: ' GATEWAY
            echo ""
            read -p 'Enter the Netmask for this device: ' NETMASK
            echo "" 
            sed -e "s;%DEVICE_NAME%;$DEVICE_NAME;g" -e "s;%UUID%;$UUID;g" -e "s;%HWADDR%;$HWADDR;g" -e "s;%IP_ADDRESS%;$IP_ADDRESS;g" -e "s;%NETMASK%;$NETMASK;g" -e "s;%GATEWAY%;$GATEWAY;g" -e "s;%DEF_ROUTE%;$DEF_ROUTE;g" ./static.template > $ETHERNET_CFG_FILE
        fi
        read -p 'Do you want to configure another device (y/n): ' CONFIGURE_ANOTHER
        echo ""
        if [ "$CONFIGURE_ANOTHER" == "n" ]; then
            break
        fi
    done

	echo "Will add the following to the machine hosts file: "
	for word in $HOSTS; do
		echo "$word"
	done    

    echo ""
    echo "Creating Network configuration files..."
	echo ""
	echo "Saving $NETWORK_CONFIG_FILE..."
	# Save network config file
	sed -e "s;%FULL_NAME%;$FULL_NAME;g" ./network.template > $NETWORK_CONFIG_FILE

	echo ""
	echo "Saving $DNS_CONFIG_FILE..."
	# Save resolv config file
	sed -e "s;%DNS_SERVER_IP%;$DNS_SERVER_IP;g" -e "s;%DOMAIN_NAME%;$DOMAIN_NAME;g" ./resolv.template > $DNS_CONFIG_FILE

	echo ""
	echo "Saving $HOSTS_CONFIG_FILE..."	
	# Save hosts config file
	sed -e "s;%IP_ADDRESS%;$IP_ADDRESS;g" -e "s;%FULL_NAME%;$FULL_NAME;g" -e "s;%SIMPLE_NAME%;$SIMPLE_NAME;g" ./hosts.template > $HOSTS_CONFIG_FILE

    for word in $HOSTS; do
        echo "$word" >> $HOSTS_CONFIG_FILE
    done

    echo ""
    echo "Network files created..."

    restartNetwork
}

#-------------------------------------------------------------------
# FMW User Creation
#-------------------------------------------------------------------
function createFmwUser(){

    if [ "$FMW_USER_NAME" == "NULL" ]; then
        echo ""
        echo "Fusion Middleware User not set..."
        echo ""
        read -p 'Enter your FMW user name: ' FMW_USER_NAME
    fi
    
    if [ "$FMW_USER_PASSWORD" == "NULL" ]; then
        echo ""
        read -s -p 'Enter your user password: ' FMW_USER_PASSWORD
    fi
    
    IS_GROUP_OINSTALL_EXISTS=`cat /etc/group | cut -d: -f1 | grep $ORACLE_INSTALL_GROUP`

    if [ "$IS_GROUP_OINSTALL_EXISTS" == "" ]; then
        echo ""
        echo "Creating Group $ORACLE_INSTALL_GROUP"
        groupadd $ORACLE_INSTALL_GROUP
    else
        echo ""
        echo "Group $ORACLE_INSTALL_GROUP already exists, skipping its creation..."
    fi
    
    IS_GROUP_DBA_EXISTS=`cat /etc/group | cut -d: -f1 | grep $ORACLE_DBA_INSTALL_GROUP`

    if [ "$IS_GROUP_DBA_EXISTS" == "" ]; then
        echo ""
        echo "Creating Group $ORACLE_DBA_INSTALL_GROUP"
        groupadd $ORACLE_DBA_INSTALL_GROUP
    else
        echo ""
        echo "Group $ORACLE_DBA_INSTALL_GROUP already exists, skipping its creation..."
    fi

    IS_USER_ORACLE_EXISTS=`cat /etc/passwd | cut -d: -f1 | grep $FMW_USER_NAME`

    if [ "$IS_USER_ORACLE_EXISTS" == "" ]; then
        echo ""
        echo "Creating User: $FMW_USER_NAME"
        useradd -g $ORACLE_INSTALL_GROUP -m $FMW_USER_NAME
        echo ""        
        echo "Setting $FMW_USER_NAME groups membership..."
        usermod -a -G $ORACLE_DBA_INSTALL_GROUP,users $FMW_USER_NAME
        echo ""        
        echo -e "$FMW_USER_PASSWORD\n$FMW_USER_PASSWORD" | (passwd --stdin $FMW_USER_NAME)
        passwd -u $FMW_USER_NAME
    else
        echo ""
        echo "User $FMW_USER_NAME already exists, skipping its creation..."
        echo ""        
        echo "Setting $FMW_USER_NAME groups membership..."
        usermod -g $ORACLE_INSTALL_GROUP -m $FMW_USER_NAME
        echo ""
        usermod -a -G $ORACLE_DBA_INSTALL_GROUP,users $FMW_USER_NAME
        echo ""
        echo -e "$FMW_USER_PASSWORD\n$FMW_USER_PASSWORD" | (passwd --stdin $FMW_USER_NAME)
        passwd -u $FMW_USER_NAME
        echo ""        
        echo "Check manually if the user belongs to groups $ORACLE_INSTALL_GROUP and $ORACLE_DBA_INSTALL_GROUP"
    fi
    
    # Creates the logs folder in the FMW home, to hold product logs
    if [ ! -d "/home/$FMW_USER_NAME/logs" ]; then
        echo ""
        echo "Creating logs directory in $FMW_USER_NAME home"
        mkdir /home/$FMW_USER_NAME/logs
        chown -R $FMW_USER_NAME /home/$FMW_USER_NAME/logs
        chgrp -R  $ORACLE_INSTALL_GROUP /home/$FMW_USER_NAME/logs
    fi
}

#-------------------------------------------------------------------
# Changing Sudoers File
#-------------------------------------------------------------------
function addUsersToSudoers(){

    if [ "$FMW_USER_NAME" == "NULL" ]; then
        echo ""
        echo "Fusion Middleware User is not set..."
        createFmwUser
    fi

cat <<EOF >"$SUDOERS_DIRECTORY/oel_sudoers"
$FMW_USER_NAME       ALL=(ALL)     NOPASSWD:ALL,/bin/su
EOF

    chmod 0440 $SUDOERS_DIRECTORY/oel_sudoers
}

#-------------------------------------------------------------------
# Restart Network Services
#-------------------------------------------------------------------
function restartNetwork(){
    echo ""
    echo "Restarting Network..."
    /etc/init.d/network restart
    /etc/init.d/sshd stop
    /etc/init.d/sshd start
}

#-------------------------------------------------------------------
# Install Required Libraries
#-------------------------------------------------------------------
function installRequiredLibs(){
    yum -y install oracle-rdbms-server-11gR2-preinstall
    yum -y install xorg-x11-apps
    yum -y install xorg-x11-server-utils
    yum -y install kernel-devel
    yum -y install kernel-uek-devel
    yum -y install binutils
    yum -y install libgcc.i686
    yum -y install libstdc++.i686
    yum -y install libaio.i686
    yum -y install libaio-devel.i686
    yum -y install unixODBC
    yum -y install unixODBC.i686
    yum -y install unixODBC-devel
    yum -y install unixODBC-devel.i686
    yum -y install elfutils-libelf-devel.x86_64
    yum -y install mksh
    yum -y install compat-libstdc++-33.i686
    yum -y install libXext
    yum -y install libXtst
    yum -y install libXext.i686
    yum -y install libXtst.i686	
    yum -y install openmotif
    yum -y install openmotif22
    yum -y install sysstat
}
 
 
#-------------------------------------------------------------------
# Install Virtual Box Additions
#-------------------------------------------------------------------
function installVBoxAdditions(){

    yum -y install kernel-uek-devel-2.6.39-200.24.1.el6uek.x86_64

    if [ "$FMW_USER_NAME" == "NULL" ]; then
        echo "Fusion Middleware User is not set..."
        createFmwUser
    fi    
    echo ""
    echo "Make sure you have the Virtual Machine CD-ROM drive mounted with the VBoxGuestAddittions.iso before proceeding..."
    echo ""
    read -p 'Press y when ready:' IS_READY

    if [ "$IS_READY" == "y" ]; then
        cd /
        if [ ! -d "$CDROM_FOLDER" ]; then
            mkdir $CDROM_FOLDER
        fi
        mount /dev/scd0 $CDROM_FOLDER
        $CDROM_FOLDER/VBoxLinuxAdditions.run
        
        # Adding FMW User to shared folder group
        usermod -a -G vboxsf $FMW_USER_NAME        
        
    fi
}

#-------------------------------------------------------------------
# Changing SSH Files
#-------------------------------------------------------------------
function configureSshAccess(){
    echo ""
    echo "Configuring SSH Access..."
    echo ""
    echo "Checking Group Permissions..."

    #IS_SSH_SET=`cat $SSH_CONFIG_FILE | grep AllowGroups`
    #if [ "$IS_SSH_SET" == "" ]; then
    #    echo ""
    #    echo "AllowGroups not set, adding to ssh_config..."
    #    echo ""
    #    echo "AllowGroups users" >> $SSH_CONFIG_FILE
    #fi

    IS_SSHD_SET=`cat $SSHD_CONFIG_FILE | grep AllowGroups`

    if [ "$IS_SSHD_SET" == "" ]; then
        echo ""
        echo "AllowGroups not set, adding to sshd_config..."
        echo ""
        echo "AllowGroups users" >> $SSHD_CONFIG_FILE
    fi
    
    restartNetwork
}

#-------------------------------------------------------------------
# Customize user´s .bashrc file
#-------------------------------------------------------------------
function customizeBashrc(){

    if [ "$FMW_USER_NAME" == "NULL" ]; then
        echo "FMW User is not set..."
        createFmwUser
    fi
    
    echo "# .bashrc" > /home/$FMW_USER_NAME/.bashrc
    echo "# Source global definitions" >> /home/$FMW_USER_NAME/.bashrc
    echo "if [ -f /etc/bashrc ]; then" >> /home/$FMW_USER_NAME/.bashrc
    echo "   . /etc/bashrc" >> /home/$FMW_USER_NAME/.bashrc
    echo "fi" >> /home/$FMW_USER_NAME/.bashrc
    echo "" >> /home/$FMW_USER_NAME/.bashrc
    echo "# User specific aliases and functions" >> /home/$FMW_USER_NAME/.bashrc
    echo "export GREP_OPTIONS='--color=auto'" >> /home/$FMW_USER_NAME/.bashrc    
}

#-------------------------------------------------------------------
# Disables OEL Firewall
#-------------------------------------------------------------------
function disableOELFirewall(){
    echo ""
    echo "WARNING!!! This will disable the Firewall and it will not run again even after reboot"
    service iptables save
    service iptables stop
    chkconfig iptables off
}

function configureDNSServer(){
    clear
    echo "This will configure DNS Server on this host"
	echo "Installing Required Libs....."
	echo ""
	yum -y install bind
	echo ""
	read -p 'Please enter the domain name for the DNS Search: ' DNS_DOMAIN_NAME
	echo ""
	read -p 'Please enter this machine IP address: ' DNS_IP_ADDRESS
	REVERSE_IP=`echo $DNS_IP_ADDRESS | awk -F'.' '{print $3"."$2"."$1}'`
	NORMAL_IP=`echo $DNS_IP_ADDRESS | awk -F'.' '{print $1"."$2"."$3}'`
	DNS_HOST=`hostname`
	SIMPLE_HOSTNAME=`hostname | awk -F'.' '{print $1}'`
	sed -e "s;%DNS_DOMAIN_NAME%;$DNS_DOMAIN_NAME;g" -e "s;%REVERSE_IP%;$REVERSE_IP;g" -e "s;%DNS_IP_ADDRESS%;$NORMAL_IP;g" ./named.template > /etc/named.conf #Save the file to this location /etc/named.conf
	sed -e "s;%DNS_HOST%;$DNS_HOST;g" -e "s;%DNS_DOMAIN_NAME%;$DNS_DOMAIN_NAME;g" ./domain.template > /var/named/$DNS_DOMAIN_NAME #Save the file to this location /var/named/mycompany.com
	sed -e "s;%DNS_HOST%;$DNS_HOST;g" -e "s;%SIMPLE_HOSTNAME%;$SIMPLE_HOSTNAME;g" ./reverse.template > /var/named/$NORMAL_IP #Save the file to this location /var/named/192.168.56
	sed -e "s;%DNS_DOMAIN_NAME%;$DNS_DOMAIN_NAME;g" -e "s;%REVERSE_IP%;$REVERSE_IP;g" -e "s;%NORMAL_IP%;$NORMAL_IP;g" ./namedboot.template > /etc/named.boot #Save the file to this location /etc/named.boot
	echo ""
	
	USER_HOST_INPUT="y"
	while [ "$USER_HOST_INPUT" != "n" ];
	do
		read -p 'Enter the host-ip you want to map in the following format: myhost-111.111.11.111 (Enter n when done): ' USER_HOST_INPUT
		if [ "$USER_HOST_INPUT" != "n" ]; then
		    HOST=`echo $USER_HOST_INPUT | awk -F'-' '{print $1}'`
		    IP=`echo $USER_HOST_INPUT | awk -F'-' '{print $2}'`
            END_IP=`echo $USER_HOST_INPUT | awk -F'.' '{print $4}'`			
			echo "$HOST    IN    A    $IP" >> /var/named/$DNS_DOMAIN_NAME #Save the file to this location /var/named/mycompany.com
			echo "$END_IP   IN    PTR    $HOST.$DNS_DOMAIN_NAME." >> /var/named/$NORMAL_IP
			echo "$END_IP   IN    PTR    $HOST." >> /var/named/$NORMAL_IP
		fi
	done
	echo ""
	echo "Stopping/Starting named service..."
	echo ""
	service named stop
    service named start
    chkconfig named on
	echo "DNS Server configured successfully for this Machine!"

}

function configureNFSServer() {
    echo ""
    echo "Configuring Shared Storage..."
    echo ""
	echo "Installing required libs..."
	echo ""
	yum -y install nfs-utils
	echo ""
	
	if [ "$FMW_USER_NAME" == "NULL" ]; then
        echo ""
        echo "Fusion Middleware User is not set..."
        createFmwUser
    fi
	
	mkdir -p $BASE_SHARED_STORE
	chown -R $FMW_USER_NAME $BASE_SHARED_STORE
	chgrp -R $ORACLE_INSTALL_GROUP $BASE_SHARED_STORE
	
	echo ""
	echo "Enter the FQDN and IPs of the hosts that will have read/write access to the shared storage."
	echo ""
	
	USER_HOST_INPUT="y"
	HOSTS=$BASE_SHARED_STORE
	IPS="portmap:"
	while [ "$USER_HOST_INPUT" != "n" ];
	do
		
		read -p 'Use the following format myhost-111.111.11.111 (Enter n when done): ' USER_HOST_INPUT
		if [ "$USER_HOST_INPUT" != "n" ]; then
			HOST=`echo $USER_HOST_INPUT | awk -F'-' '{print $1}'`
		    IP=`echo $USER_HOST_INPUT | awk -F'-' '{print $2}'`
		    HOSTS="$HOSTS|$HOST(rw) "
			IPS="$IPS|$IP, "
		fi
	done


    #TODO: mudar os hosts abaixo por variáveis
    echo $HOSTS > /etc/exports
    #TODO: Sempre deny all
    echo "portmap:ALL" > /etc/hosts.deny
    #mudar os hosts abaixo por variáveis
    echo "$IPSlocalhost" > /etc/hosts.allow
	echo ""
	echo "Stopping/Starting Services"
	
	#Stop all NFS related services
	service nfslock stop
	service nfs stop
	service rpcidmapd stop
	service rpcbind stop
	service portreserve stop
    
    #Start all NFS related services
    service portreserve start
    service rpcbind start
    service rpcidmapd start
    service nfs start
    service nfslock start
	
	#Configure NFS services to start after bootup
	chkconfig portreserve on
    chkconfig rpcbind on
    chkconfig rpcidmapd on
    chkconfig nfs on
    chkconfig nfslock on
}

function configureNFSClient(){
    clear
	echo ""
	echo "This will mount and map the shared storage on this host"
	
	if [ "$FMW_USER_NAME" == "NULL" ]; then
        echo ""
        echo "Fusion Middleware User is not set..."
        createFmwUser
    fi
	
	echo ""
	read -p "Enter the NFS Server hostname: " NFS_HOST
	echo ""
	
	mkdir -p $BASE_SHARED_STORE
	chown -R $FMW_USER_NAME $BASE_SHARED_STORE
	chgrp -R $ORACLE_INSTALL_GROUP $BASE_SHARED_STORE
	
	mount -t nfs $NFS_HOST:$BASE_SHARED_STORE $BASE_SHARED_STORE
	
	echo "$NFS_HOST:$BASE_SHARED_STORE  $BASE_SHARED_STORE  nfs  defaults   1 2" >> $FSTAB_CONFIG_FILE

}

function printKernelRecommendedValues(){

    clear
    echo "## Recommended Kernel Parameters for FMW R2 ##"
    echo ""
    echo "semmsl: $RECOM_SEMMSL"
    echo "semmns: $RECOM_SEMMNS"
    echo "semopm: $RECOM_SEMOPM"
    echo "semmni: $RECOM_SEMMNI"
    echo "shmall: $RECOM_SHMALL"
    echo "shmmax: $RECOM_SHMMAX"
    echo "shmmni: $RECOM_SHMMNI"
    echo "file-max: $RECOM_FILE_MAX"
    echo "ip-local-port-range-min: $RECOM_IP_LOCAL_PORT_RANGE_MIN"
    echo "ip-local-port-range-max: $RECOM_IP_LOCAL_PORT_RANGE_MAX"
    echo "rmem_default: $RECOM_RMEM_DEFAULT"
    echo "rmem_max: $RECOM_RMEM_MAX"
    echo "wmem_default: $RECOM_WMEM_DEFAULT"
    echo "wmem_max: $RECOM_WMEM_MAX"
    echo "aio_max_nr: $RECOM_AIO_MAX_NR"
    echo ""

}

function fixKernelParameters() {

    #Creates the file with original entries
    echo "# Kernel sysctl configuration file Customization for Oracle Enterprise Linux" > $KERNEL_SYSCTL_FILE
    echo "# For binary values, 0 is disabled, 1 is enabled." >> $KERNEL_SYSCTL_FILE
    echo "" >> $KERNEL_SYSCTL_FILE
    echo "# Controls IP packet forwarding" >> $KERNEL_SYSCTL_FILE
    echo "net.ipv4.ip_forward = 0" >> $KERNEL_SYSCTL_FILE
    echo "" >> $KERNEL_SYSCTL_FILE
    echo "# Controls source route verification" >> $KERNEL_SYSCTL_FILE
    echo "net.ipv4.conf.default.rp_filter = 1" >> $KERNEL_SYSCTL_FILE
    echo "" >> $KERNEL_SYSCTL_FILE
    echo "# Do not accept source routing" >> $KERNEL_SYSCTL_FILE
    echo "net.ipv4.conf.default.accept_source_route = 0" >> $KERNEL_SYSCTL_FILE
    echo "" >> $KERNEL_SYSCTL_FILE    
    echo "# Controls the System Request debugging functionality of the kernel" >> $KERNEL_SYSCTL_FILE
    echo "kernel.sysrq = 0" >> $KERNEL_SYSCTL_FILE
    echo "" >> $KERNEL_SYSCTL_FILE    
    echo "# Controls whether core dumps will append the PID to the core filename." >> $KERNEL_SYSCTL_FILE
    echo "# Useful for debugging multi-threaded applications." >> $KERNEL_SYSCTL_FILE
    echo "kernel.core_uses_pid = 1" >> $KERNEL_SYSCTL_FILE
    echo "" >> $KERNEL_SYSCTL_FILE    
    echo "# Controls the use of TCP syncookies" >> $KERNEL_SYSCTL_FILE
    echo "net.ipv4.tcp_syncookies = 1" >> $KERNEL_SYSCTL_FILE
    echo "" >> $KERNEL_SYSCTL_FILE    
    echo "# Controls the default maxmimum size of a mesage queue" >> $KERNEL_SYSCTL_FILE
    echo "kernel.msgmnb = 65536" >> $KERNEL_SYSCTL_FILE
    echo "" >> $KERNEL_SYSCTL_FILE    
    echo "# Controls the maximum size of a message, in bytes" >> $KERNEL_SYSCTL_FILE
    echo "kernel.msgmax = 65536    " >> $KERNEL_SYSCTL_FILE
    echo "" >> $KERNEL_SYSCTL_FILE    

    CONCAT_SEMM=
    CONCAT_LOCAL_PORT=
    
    if [ $READ_SEMMSL -lt $RECOM_SEMMSL  ]; then
        CONCAT_SEMM="$RECOM_SEMMSL"
    else
        CONCAT_SEMM="$READ_SEMMSL"
    fi

    if [ $READ_SEMMNS -lt $RECOM_SEMMNS  ]; then
        CONCAT_SEMM="$CONCAT_SEMM $RECOM_SEMMNS"
    else
        CONCAT_SEMM="$CONCAT_SEMM $READ_SEMMNS"
    fi

    if [ $READ_SEMOPM -lt $RECOM_SEMOPM  ]; then
        CONCAT_SEMM="$CONCAT_SEMM $RECOM_SEMOPM"
    else
        CONCAT_SEMM="$CONCAT_SEMM $READ_SEMOPM"
    fi

    if [ $READ_SEMMNI -lt $RECOM_SEMMNI  ]; then
        CONCAT_SEMM="$CONCAT_SEMM $RECOM_SEMMNI"
    else
        CONCAT_SEMM="$CONCAT_SEMM $READ_SEMMNI"
    fi
    
    echo "kernel.sem = $CONCAT_SEMM" >> $KERNEL_SYSCTL_FILE
        
    if [ $READ_SHMALL -lt $RECOM_SHMALL  ]; then
        echo "kernel.shmall = $RECOM_SHMALL" >> $KERNEL_SYSCTL_FILE
    else
        echo "kernel.shmall = $READ_SHMALL" >> $KERNEL_SYSCTL_FILE
    fi

    if [ $READ_SHMMAX -lt $RECOM_SHMMAX  ]; then
        echo "kernel.shmmax = $RECOM_SHMMAX" >> $KERNEL_SYSCTL_FILE
    else
        echo "kernel.shmmax = $READ_SHMMAX" >> $KERNEL_SYSCTL_FILE
    fi

    if [ $READ_SHMMNI -lt $RECOM_SHMMNI  ]; then
        echo "kernel.shmmni = $RECOM_SHMMNI" >> $KERNEL_SYSCTL_FILE
    else
        echo "kernel.shmmni = $READ_SHMMNI" >> $KERNEL_SYSCTL_FILE
    fi

    if [ $READ_FILE_MAX -lt $RECOM_FILE_MAX  ]; then
        echo "fs.file-max = $RECOM_FILE_MAX" >> $KERNEL_SYSCTL_FILE
    else
        echo "fs.file-max = $READ_FILE_MAX" >> $KERNEL_SYSCTL_FILE
    fi

    if [ $READ_IP_LOCAL_PORT_RANGE_MIN -lt $RECOM_IP_LOCAL_PORT_RANGE_MIN  ]; then
        CONCAT_LOCAL_PORT="$RECOM_IP_LOCAL_PORT_RANGE_MIN "
    else
        CONCAT_LOCAL_PORT="$READ_IP_LOCAL_PORT_RANGE_MIN "
    fi

    if [ $READ_IP_LOCAL_PORT_RANGE_MAX -lt $RECOM_IP_LOCAL_PORT_RANGE_MAX  ]; then
        CONCAT_LOCAL_PORT="$CONCAT_LOCAL_PORT$RECOM_IP_LOCAL_PORT_RANGE_MAX "
    else
        CONCAT_LOCAL_PORT="$CONCAT_LOCAL_PORT$READ_IP_LOCAL_PORT_RANGE_MAX "
    fi
    
    echo "net.ipv4.ip_local_port_range = $CONCAT_LOCAL_PORT" >> $KERNEL_SYSCTL_FILE

    if [ $READ_RMEM_DEFAULT -lt $RECOM_RMEM_DEFAULT  ]; then
        echo "net.core.rmem_default = $RECOM_RMEM_DEFAULT" >> $KERNEL_SYSCTL_FILE
    else
        echo "net.core.rmem_default = $READ_RMEM_DEFAULT" >> $KERNEL_SYSCTL_FILE
    fi

    if [ $READ_RMEM_MAX -lt $RECOM_RMEM_MAX  ]; then
        echo "net.core.rmem_max = $RECOM_RMEM_MAX" >> $KERNEL_SYSCTL_FILE
    else
        echo "net.core.rmem_max = $READ_RMEM_MAX" >> $KERNEL_SYSCTL_FILE
    fi

    if [ $READ_WMEM_DEFAULT -lt $RECOM_WMEM_DEFAULT  ]; then
        echo "net.core.wmem_default = $RECOM_WMEM_DEFAULT" >> $KERNEL_SYSCTL_FILE
    else
        echo "net.core.wmem_default = $READ_WMEM_DEFAULT" >> $KERNEL_SYSCTL_FILE
    fi

    if [ $READ_WMEM_MAX -lt $RECOM_WMEM_MAX  ]; then
        echo "net.core.wmem_max = $RECOM_WMEM_MAX" >> $KERNEL_SYSCTL_FILE
    else
        echo "net.core.wmem_max = $READ_WMEM_MAX" >> $KERNEL_SYSCTL_FILE
    fi
    
    if [ $READ_AIO_MAX_NR -lt $RECOM_AIO_MAX_NR  ]; then
        echo "fs.aio-max-nr = $RECOM_AIO_MAX_NR" >> $KERNEL_SYSCTL_FILE    
    else
        echo "fs.aio-max-nr = $READ_AIO_MAX_NR" >> $KERNEL_SYSCTL_FILE        
    fi

    #Reloading the changes
    sysctl -p
}

function configureKernelParameters(){

    #Read SEMM Values
    READ_SEMMSL=`cat /proc/sys/kernel/sem | awk '{print $1}'`

    READ_SEMMNS=`cat /proc/sys/kernel/sem | awk '{print $2}'`

    READ_SEMOPM=`cat /proc/sys/kernel/sem | awk '{print $3}'`

    READ_SEMMNI=`cat /proc/sys/kernel/sem | awk '{print $4}'`

    #Read SHMALL Value
    READ_SHMALL=`cat /proc/sys/kernel/shmall`

    #Read SHMMAX value
    READ_SHMMAX=`cat /proc/sys/kernel/shmmax`

    #Read SHMMNI value
    READ_SHMMNI=`cat /proc/sys/kernel/shmmni`

    #Read FILE-MAX value
    READ_FILE_MAX=`cat /proc/sys/fs/file-max`

    #Read IP_LOCAL_PORT_RANGE value
    READ_IP_LOCAL_PORT_RANGE=`cat /proc/sys/net/ipv4/ip_local_port_range`

    #Read IP_LOCAL_PORT_RANGE values
    READ_IP_LOCAL_PORT_RANGE_MIN=`cat /proc/sys/net/ipv4/ip_local_port_range | awk '{print $1}'`

    READ_IP_LOCAL_PORT_RANGE_MAX=`cat /proc/sys/net/ipv4/ip_local_port_range | awk '{print $2}'`

    #Read RMEM_DEFAULT
    READ_RMEM_DEFAULT=`cat /proc/sys/net/core/rmem_default`

    #Read RMEM_MAX
    READ_RMEM_MAX=`cat /proc/sys/net/core/rmem_max`

    #Read WMEM_DEFAULT
    READ_WMEM_DEFAULT=`cat /proc/sys/net/core/wmem_default`

    #Read WMEM_MAX
    READ_WMEM_MAX=`cat /proc/sys/net/core/wmem_max`

    #Read AIO-MAX-NR
    READ_AIO_MAX_NR=`cat /proc/sys/fs/aio-max-nr`

    if [ $READ_SEMMSL -lt $RECOM_SEMMSL  ]; then
        echo "FAIL: semmsl($READ_SEMMSL)  smaller that the recommended value of $RECOM_SEMMSL."
    fi

    if [ $READ_SEMMNS -lt $RECOM_SEMMNS  ]; then
        echo "FAIL: semmns($READ_SEMMNS) smaller that the recommended value of $RECOM_SEMMNS."
    fi

    if [ $READ_SEMOPM -lt $RECOM_SEMOPM  ]; then
        echo "FAIL: semopm($READ_SEMOPM) smaller that the recommended value of $RECOM_SEMOPM."
    fi

    if [ $READ_SEMMNI -lt $RECOM_SEMMNI  ]; then
        echo "FAIL: semmni($READ_SEMMNI) smaller that the recommended value of $RECOM_SEMMNI."
    fi

    if [ $READ_SHMALL -lt $RECOM_SHMALL  ]; then
        echo "FAIL: shmall($READ_SHMALL) smaller that the recommended value of $RECOM_SHMALL"
    fi

    if [ $READ_SHMMAX -lt $RECOM_SHMMAX  ]; then
        echo "FAIL: shmmax($READ_SHMMAX) smaller that the recommended value of $RECOM_SHMMAX"
    fi

    if [ $READ_SHMMNI -lt $RECOM_SHMMNI  ]; then
        echo "FAIL: shmmni($READ_SHMMNI) smaller that the recommended value of $RECOM_SHMMNI"
    fi

    if [ $READ_FILE_MAX -lt $RECOM_FILE_MAX  ]; then
        echo "FAIL: file-max($READ_FILE_MAX) smaller that the recommended value of $RECOM_FILE_MAX"
    fi

    if [ $READ_IP_LOCAL_PORT_RANGE_MIN -lt $RECOM_IP_LOCAL_PORT_RANGE_MIN  ]; then
        echo "FAIL: ip-local-port-range-min($READ_IP_LOCAL_PORT_RANGE_MIN) smaller that the recommended value of $RECOM_IP_LOCAL_PORT_RANGE_MIN"
    fi

    if [ $READ_IP_LOCAL_PORT_RANGE_MAX -lt $RECOM_IP_LOCAL_PORT_RANGE_MAX  ]; then
        echo "FAIL: ip-local-port-range-max($READ_IP_LOCAL_PORT_RANGE_MAX) smaller that the recommended value of $RECOM_IP_LOCAL_PORT_RANGE_MAX"
    fi

    if [ $READ_RMEM_DEFAULT -lt $RECOM_RMEM_DEFAULT  ]; then
        echo "FAIL: rmem_default($READ_RMEM_DEFAULT) smaller that the recommended value of $RECOM_RMEM_DEFAULT"
    fi

    if [ $READ_RMEM_MAX -lt $RECOM_RMEM_MAX  ]; then
        echo "FAIL: rmem_max($READ_RMEM_MAX) smaller that the recommended value of $RECOM_RMEM_MAX"
    fi

    if [ $READ_WMEM_DEFAULT -lt $RECOM_WMEM_DEFAULT  ]; then
        echo "FAIL: wmem_default($READ_WMEM_DEFAULT) smaller that the recommended value of $RECOM_WMEM_DEFAULT"
    fi

    if [ $READ_WMEM_MAX -lt $RECOM_WMEM_MAX  ]; then
        echo "FAIL: wmem_max($READ_WMEM_MAX) smaller that the recommended value of $RECOM_WMEM_MAX"
    fi

    if [ $READ_AIO_MAX_NR -lt $RECOM_AIO_MAX_NR  ]; then
        echo "FAIL: aio_max_nr($READ_AIO_MAX_NR) smaller that the recommended value of $RECOM_AIO_MAX_NR"
    fi

    EXIT_KERNEL_FIX=0

    while [ $EXIT_KERNEL_FIX = 0 ]
    do
        clear
        echo "## Kernel Parameters Sub-Menu ##"
        echo ""
        echo "Choose an option below:"
        echo "1 - Print Recommended Kernel Parameter values"
        echo "2 - Fix Failed Kernel Parameters with Recommended Values"
        echo "3 - Back to main Menu"
        echo ""
        read -p "Enter your option: " FIX_KERNEL_OPTION

        case "$FIX_KERNEL_OPTION" in

            1)
                printKernelRecommendedValues
                read -p "Press any key to continue..." XPTO
                ;;
            2)
                fixKernelParameters
                read -p "Kernel Parameters set, Press any key to continue..." XPTO
                ;;
            3)
                EXIT_KERNEL_FIX=1
                echo "Exiting Kernel Parameters Sub-Menu..."
                sleep 3
                ;;
        esac
    done

}

function configureUserLimits(){

    if [ "$FMW_USER_NAME" == "NULL" ]; then
        echo "Fusion Middleware User is not set..."
        createFmwUser
    fi
        
    echo "# OEL Configure Machine Script setting for nofile soft limit is 1024" > $USER_LIMITS_FILE
    echo "$FMW_USER_NAME   soft   nofile    $NOFILE_SOFT_LIMIT" >> $USER_LIMITS_FILE

    echo "# OEL Configure Machine Script setting for nofile hard limit is 65536" >> $USER_LIMITS_FILE
    echo "$FMW_USER_NAME   hard   nofile    $NOFILE_HARD_LIMIT" >> $USER_LIMITS_FILE

    echo "# OEL Configure Machine Script setting for nproc soft limit is 2047" >> $USER_LIMITS_FILE
    echo "$FMW_USER_NAME   soft   nproc    $NPROC_SOFT_LIMIT" >> $USER_LIMITS_FILE

    echo "# OEL Configure Machine Script setting for nproc hard limit is 16384" >> $USER_LIMITS_FILE
    echo "$FMW_USER_NAME   hard   nproc    $NPROC_HARD_LIMIT" >> $USER_LIMITS_FILE

    echo "# OEL Configure Machine Script setting for stack soft limit is 10240KB" >> $USER_LIMITS_FILE
    echo "$FMW_USER_NAME   soft   stack    $STACK_SOFT_LIMIT" >> $USER_LIMITS_FILE

    echo "# OEL Configure Machine Script setting for stack hard limit is 32768KB" >> $USER_LIMITS_FILE
    echo "$FMW_USER_NAME   hard   stack    $STACK_HARD_LIMIT" >> $USER_LIMITS_FILE

}

#-------------------------------------------------------------------
# Menu
#-------------------------------------------------------------------
FIN=0
while [ $FIN = 0 ]
do
    clear
    echo "########################################################"
    echo "# Welcome to the OEL Basic Server Configuration Script #"
    echo "########################################################"
    echo ""
    echo " 0  - Back up Configuration Files (Always run this)"
    echo " 1  - Configure Network"
	echo " 2  - Configure DNS Server"
    echo " 3  - Create FMW User"
    echo " 4  - Configure NFS Server"
	echo " 5  - Configure NFS Clients"
    echo " 6  - Add user to SUDOERS"
    echo " 7  - Install FMW Required Libs"
    echo " 8  - Install VBox Additions"
    echo " 9  - Configure SSH Access"
    echo " 10  - Customize FMW User .bashrc"
    echo " 11  - Configure Kernel Parameters"
    echo " 12  - Configure User Limits"
    echo " 13 - Disable OEL Firewall"
    echo " u  - Print Usage Message"    
    echo " x  - Exit"
    echo ""
    read -p " Choose one option: " MENU_OPT

    case "$MENU_OPT" in
        0)
            backUpFiles
            read -p "Configuration Files Saved, press any key to continue..." XPTO
            ;;
        1)
            configureNetwork                
            read -p "Network configured, press any key to continue..." XPTO
            ;;
		2) 
		    configureDNSServer
		    read -p "DNS Server configuration finished, press any key to continue..." XPTO
		    ;;		   
		3)  
		    createFmwUser
            read -p "FMW user created, press any key to continue..." XPTO
            ;;
        4)
		    configureNFSServer
			read -p "NFS Server configured. Don't forget to update the NFS clients to mount the shared store, run '5) Configure NFS Clients' task, press any key to continue... "
			;;
		5)
		    configureNFSClient
			read -p "NFS Clients configured, press any key to continue..."
			;;
        6)    
    		addUsersToSudoers
            read -p "Users added to Sudoers, press any key to continue..." XPTO
            ;;
        7)
            installRequiredLibs
            read -p "Required Libs Installed, press any key to continue..." XPTO
            ;;
        8)
            installVBoxAdditions
            read -p "VBox Additions installed, press any key to continue..." XPTO
            ;;
        9)
            configureSshAccess
            read -p "SSH Access configured, press any key to continue..." XPTO
            ;;
        10)
            customizeBashrc
            read -p "Bashrc Customized, press any key to continue..." XPTO
            ;;
        11)
            configureKernelParameters
            read -p "Kernel Parameters Configured, press any key to continue..." XPTO
            ;;
        12)
            configureUserLimits
            read -p "User Limits Configured, press any key to continue..." XPTO
            ;;
        13)
            disableOELFirewall
            read -p "Firewall Disabled, press any key to continue..." XPTO
            ;;
        u)
            usage
            read -p "Press any key to continue..." XPTO            
            ;;            
        x)
            echo "Exiting program..."
            sleep 3
            FIN=1
            ;;            
        *)
            echo "Option not available..."
            usage
            sleep 3
            ;;
    esac
done

