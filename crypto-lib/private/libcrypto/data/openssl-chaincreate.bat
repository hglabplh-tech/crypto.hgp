openssl req -new -newkey rsa:2048 -nodes -out ca.csr -set_serial 05 -keyout ca.key
openssl x509 -trustout -signkey ca.key -days 365 -req -set_serial 05 -in ca.csr -out ca.pem
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr
openssl x509 -req -in client.csr -days 1000 -CA ca.pem -CAkey ca.key -set_serial 05 > client.cer
openssl rsa -inform PEM -outform DER -in ca.key -out freeware-ca-key%1.der
openssl rsa -inform PEM -outform DER -in client.key -out freeware-user-key%1.der
openssl x509 -inform PEM -outform DER -in client.cer -out freeware-user-cert%1.der
openssl x509 -inform PEM -outform DER -in ca.pem  -out freeware-ca-cert%1.der