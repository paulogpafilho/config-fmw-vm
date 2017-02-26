#!/bin/bash

export SERVER_NAME=nodemanager

export LOGS_HOME=/home/oracle/logs

export JAVA_OPTIONS="-Dweblogic.Stderr=/home/oracle/logs/${SERVER_NAME}.err -Dweblogic.security.allowCryptoJDefaultJCEVerification=true -Dweblogic.security.allowCryptoJDefaultPRNG=true -Djava.security.egd=file:/dev/./urandom "

export WL_HOME="/u01/oracle/Middleware/wlserver_10.3"

nohup ${WL_HOME}/server/bin/startNodeManager.sh > ${LOGS_HOME}/${SERVER_NAME}.out 2>&1 &

echo "tail -200f ${LOGS_HOME}/${SERVER_NAME}.out"
