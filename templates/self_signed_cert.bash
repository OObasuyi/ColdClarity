# Generate the Root CA certificate
openssl genrsa -aes256 -passout pass:CREATE_A_SECURE_PASSWORD -out ca.pass.key 4096
openssl rsa -passin pass:CREATE_A_SECURE_PASSWORD -in ca.pass.key -out ca.key
openssl req -new -x509 -days 1095 -key ca.key -out ca.crt -subj "/CN=$HOSTNAME"

# create client cert
openssl genrsa -aes256 -passout pass:CREATE_A_SECURE_PASSWORD -out ise_client_key.pass.key 4096
openssl rsa -passin pass:CREATE_A_SECURE_PASSWORD -in ise_client_key.pass.key -out ise_client_key.key

# PLEASE EDIT THE SAN.cnf FILE APPROPRIATELY
openssl req -new -key ise_client_key.key -out ise_client_cert.csr -config san.cnf
openssl req -in ise_client_cert.csr -text -noout

# self sign the cert for 3 years!
openssl x509 -req -days 365 -in ise_client_cert.csr -CA ca.crt -CAkey ca.key -out ise_client_cert.crt -CAcreateserial -req
openssl x509  -in ise_client_cert.crt -text -noout

# create a pk12(identity) cert with a exportable key password protected
cat ise_client_key.key ise_client_cert.crt ca.crt > ise_client_cert.pem
openssl pkcs12 -export -out ise_client_cert.pfx -inkey ise_client_key.key -in ise_client_cert.pem -certfile ca.crt

# Give ISE the Root CA cert and when importing the self-signed cert make sure you elect to use the cert for admin auth.
# you can delete all of the private keys. as you only need to keep the PFX and remember the password to use it.