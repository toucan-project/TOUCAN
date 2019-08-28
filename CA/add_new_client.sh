#!/bin/bash

# generate random name
RAND="$(head -c 200 /dev/urandom| tr -dC '[:xdigit:]' | head -c 5)"

# we need to log some things
echo 'What is the node IP you are generating the certificates for?'
echo '**if you deploying for the syslog-ng server, use kip.open.net**'
read ip

echo "${IP}:${RAND}" >> enrolled-hosts

cd managed_certificates
# create certificate and key request
openssl req -nodes -new -x509 -keyout clientkey-${RAND}.pem -out clientreq-${RAND}.pem -days 730 -config openssl.cnf
openssl x509 -x509toreq -in clientreq-${RAND}.pem -signkey clientkey-${RAND}.pem -out tmp-${RAND}.pem

# certify the credentials
ansible-vault decrypt private/cakey.pem cacert.pem

while ! [[ "$?" -eq 0 ]]
do
    ansible-vault decrypt private/cakey.pem cacert.pem
done

openssl ca -config openssl.cnf -batch -policy policy_anything -out clientcert-${RAND}.pem -infiles tmp-${RAND}.pem

rm tmp-${RAND}.pem

echo 'Please use same vault secret for encrypting the files!'
ansible-vault encrypt private/cakey.pem cacert.pem clientcert-${RAND}.pem clientkey-${RAND}.pem
while ! [[ "$?" -eq 0 ]]
do
    ansible-vault encrypt private/cakey.pem cacert.pem clientcert-${RAND}.pem clientkey-${RAND}.pem
done
echo "When deploying a new node, enter this identifier ${RAND}"
