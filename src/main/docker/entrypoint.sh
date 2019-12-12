#!/bin/sh
set -e
echo "---------------------------------OPTS------------------------------------"
echo "JAVA_OPTS="$JAVA_OPTS
echo "WAIT_FOR_IT="$WAIT_FOR_IT
echo "-------------------------------------------------------------------------"

for i in $WAIT_FOR_IT;
    do ./wait-for-it.sh $i -t 3600;
done

java $JAVA_OPTS -Djava.security.egd=file:/dev/./urandom -jar ./app.jar