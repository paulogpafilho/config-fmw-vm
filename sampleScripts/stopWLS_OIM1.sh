export SERVER_NAME="WLS_OIM1"

export JAVA_OPTIONS="-Dweblogic.Stderr=/home/oracle/logs/${SERVER_NAME}.err -Dweblogic.security.allowCryptoJDefaultJCEVerification=true -Dweblogic.security.allowCryptoJDefaultPRNG=true -Djava.security.egd=file:/dev/./urandom "

export ADMIN_URL="t3://uranium.mycompany.com:7001"

export ORACLE_HOME="/u01/oracle/Middleware/user_projects/domains/OIMDomain"

nohup ${ORACLE_HOME}/bin/stopManagedWebLogic.sh ${SERVER_NAME} ${ADMIN_URL} >> /home/oracle/logs/${SERVER_NAME}.out 2>&1 &

echo "tail -200f /home/oracle/logs/${SERVER_NAME}.out"
