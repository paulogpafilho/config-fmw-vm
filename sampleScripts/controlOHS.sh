#!/bin/bash
export ORACLE_HOME=/u01/oracle/Middleware/Oracle_WT1;
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$ORACLE_HOME/lib:$ORACLE_HOME/opmn/lib;
export ORACLE_INSTANCE=$ORACLE_HOME/instances/instance1;
export OPMN_HOME=$ORACLE_HOME/opmn

nohup $OPMN_HOME/bin/opmn >> /home/oracle/logs/opmn.out 2>&1 &

sleep 3

FIN=0
while [ $FIN = 0 ]
do

    clear

    $ORACLE_HOME/opmn/bin/opmnctl status

    echo "" 

    echo "Choose an option below to start:"

    echo ""

    echo "(1) - Starts OHS"
    echo "(2) - Stops OHS"

    echo ""

    read -p 'Option:' USER_OPTION
    
    if [ "$USER_OPTION" == "1" ]; then
        echo ""
        echo "Starting OHS..."
        $ORACLE_HOME/opmn/bin/opmnctl startproc process-type=OHS
    elif [ "$USER_OPTION" == "2" ]; then
        echo ""
        echo "Stopping OHS..."
        $ORACLE_HOME/opmn/bin/opmnctl stopproc process-type=OHS
    else
        echo ""
        echo "Option not recognized..."
    fi
done
