#!/bin/bash

OTD_ADMIN_HOME=/u01/oracle/Middleware/Oracle_OTD1/instances/AdminServer/admin-server
OTD_SERVER_HOME=/u01/oracle/Middleware/Oracle_OTD1/instances/AdminServer/net-IDSTORE_LDAP

while true;
do

    clear

    NR_ADMIN_INSTANCES=`sudo ps -ef | grep trafficd | grep admin-server | wc | cut -c7`
    NR_SERVER_INSTANCES=`sudo ps -ef | grep trafficd | grep net-IDSTORE_LDAP | wc | cut -c7`

    if [ $NR_ADMIN_INSTANCES -gt 0 ]; then
        echo "OTD AdminServer is RUNNING..."
    else
        echo "OTD AdminServer is SHUTDOWN..."
    fi

    echo ""

    if [ $NR_SERVER_INSTANCES -gt 0 ]; then
        echo "OTD Server is RUNNING..."
    else
        echo "OTD Server is SHUTDOWN..."
    fi


    echo ""
    echo "Choose an option below:"
    echo "1 - Start AdminServer"
    echo "2 - Stop AdminServer"
    echo "3 - Start OTD Server"
    echo "4 - Stop OTD Server"
    echo ""
    read -p "Enter your option: " USR_OPTION

    echo ""

    if [ "$USR_OPTION" == "1" ]; then
        sudo $OTD_ADMIN_HOME/bin/startserv
    elif [ "$USR_OPTION" == "2" ]; then
        sudo $OTD_ADMIN_HOME/bin/stopserv
    elif [ "$USR_OPTION" == "3" ]; then
        sudo $OTD_SERVER_HOME/bin/startserv
    elif [ "$USR_OPTION" == "4" ]; then
        sudo $OTD_SERVER_HOME/bin/stopserv
    fi

    sleep 3

done
