export SERVER_NAME="AdminServer"

export JAVA_OPTIONS="-Dweblogic.Stderr=/home/oracle/logs/AdminServer.err -Dweblogic.security.allowCryptoJDefaultJCEVerification=true -Dweblogic.security.allowCryptoJDefaultPRNG=true -Djava.security.egd=file:/dev/./urandom "

export ORACLE_HOME="/u01/oracle/Middleware/user_projects/domains/OIMDomain"

nohup ${ORACLE_HOME}/bin/stopWebLogic.sh >> /home/oracle/logs/${SERVER_NAME}.out 2>&1 &

echo "tail -200f /home/oracle/logs/${SERVER_NAME}.out"
