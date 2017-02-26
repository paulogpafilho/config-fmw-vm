export OUD_INSTANCE_HOME=/u01/oracle/Middleware/OUD_Instances/oud2/OUD

FIN=0
while [ $FIN = 0 ]
do
    clear
    $OUD_INSTANCE_HOME/bin/status -n

    echo "View the server logs at:"
    echo ""
    echo "tail -200f $OUD_INSTANCE_HOME/logs/server.out"
    echo ""
    echo "Choose an option below:"
    echo ""

    echo "(1) - Starts OUD"
    echo "(2) - Stops OUD"
    echo "(3) - Restart OUD"
    echo ""

    read -p 'Option:' USER_OPTION

    if [ "$USER_OPTION" == "1" ]; then
        echo ""
        echo "Starting OUD..."
        $OUD_INSTANCE_HOME/bin/start-ds
        sleep 3 
    elif [ "$USER_OPTION" == "2" ]; then
        echo ""
        echo "Stopping OUD..."
        $OUD_INSTANCE_HOME/bin/stop-ds
        sleep 3
    elif [ "$USER_OPTION" == "3" ]; then
        echo ""
        echo "Restarting OUD..."
        $OUD_INSTANCE_HOME/bin/stop-ds --restart
        sleep 3
    else
        echo ""
        echo "Option not recognized..."
    fi
done

