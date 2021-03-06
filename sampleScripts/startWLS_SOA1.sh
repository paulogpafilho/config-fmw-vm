export SERVER_NAME="WLS_SOA1"
export JAVA_OPTIONS="-Dweblogic.Stderr=/home/oracle/logs/${SERVER_NAME}.err -Dweblogic.security.allowCryptoJDefaultJCEVerification=true -Dweblogic.security.allowCryptoJDefaultPRNG=true -Djava.security.egd=file:/dev/./urandom -Dtangosol.coherence.wka1=beryllium.mycompany.com -Dtangosol.coherence.wka2=uranium.mycompany.com -Dtangosol.coherence.localhost=beryllium.mycompany.com"

export ADMIN_URL="http://uranium.mycompany.com:7001"

nohup /u01/oracle/Middleware/user_projects/domains/OIMDomain/bin/startManagedWebLogic.sh ${SERVER_NAME} ${ADMIN_URL} >> /home/oracle/logs/${SERVER_NAME}.out 2>&1 &
echo "tail -200f /home/oracle/logs/${SERVER_NAME}.out"

