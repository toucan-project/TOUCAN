mkdir certs crl newcerts private
cp /dev/null index.txt
openssl req -new -x509 -keyout private/cakey.pem -out cacert.pem -days 1825 -config openssl.cnf
openssl req -nodes -new -x509 -keyout serverkey.pem -out serverreq.pem -days 730 -config openssl.cnf
openssl x509 -x509toreq -in serverreq.pem -signkey serverkey.pem -out tmp.pem
openssl ca -config openssl.cnf -policy policy_anything -out servercert.pem -infiles tmp.pem
cp index.txt index.txt.attr
openssl ca -config openssl.cnf -policy policy_anything -out servercert.pem -infiles tmp.pem
rm tmp.pem
openssl req -nodes -new -x509 -keyout clientkey.pem -out clientreq.pem -days 730 -config openssl.cnf
openssl x509 -x509toreq -in clientreq.pem -signkey clientkey.pem -out tmp.pem
openssl ca -config openssl.cnf -policy policy_anything -out clientcert.pem -infiles tmp.pem

