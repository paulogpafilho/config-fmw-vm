#!/bin/bash

export ORACLE_OWNER=oracle
export ORACLE_SID=orcl
export ORACLE_HOME=/u02/app/oracle/product/11.2.0/dbhome_1

$ORACLE_HOME/bin/lsnrctl start


while true;
do

    clear
	
	$ORACLE_HOME/bin/lsnrctl status
	
	echo ""
	echo "-----------------------------------------------------------------------"
	echo ""

    INSTANCE_STATUS=`$ORACLE_HOME/bin/lsnrctl status | grep READY | wc | cut -c7`

    if [ $INSTANCE_STATUS -gt 0 ]; then
        echo "Database is RUNNING..."
    else
        echo "Database is SHUTDOWN..."
    fi

    echo ""
    echo "Choose an option below:"
    echo "1 - Start Database"
    echo "2 - Stop Database"
    echo ""
    read -p "Enter your option: " USR_OPTION

    echo ""

    if [ "$USR_OPTION" == "1" ]; then
$ORACLE_HOME/bin/sqlplus '/as sysdba' << EOF
startup;
EOF
    elif [ "$USR_OPTION" == "2" ]; then
$ORACLE_HOME/bin/sqlplus '/as sysdba' << EOF
shutdown immediate;
quit;
EOF
    fi

    sleep 3
	
    

done
