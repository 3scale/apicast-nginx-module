echo "*****************  Certs creation  *************************"

function echo {
  COLOR="\e[93m";
  ENDCOLOR="\e[0m";
  printf "$COLOR%b$ENDCOLOR\n" "$1";
}

export CERT_FOLDER="$(pwd)/certs"
export DOMAIN="subca.acalustra.com"

mkdir -p $CERT_FOLDER
rm -rf $CERT_FOLDER/*
cd $CERT_FOLDER

echo "Certs creation on folder: $CERT_FOLDER"

echo ">> SSL create CA cert"
openssl genrsa -out rootCA.key 4096
openssl req -batch -new -x509 -nodes -subj "/CN=root.ca" \
  -extensions v3_ca \
  -key rootCA.key -sha256 -days 1024 -out rootCA.pem

echo ">> Intermediate  CA cert"
openssl genrsa -out subCA.key 4096
openssl req -batch -new -x509 -subj "/CN=sub.ca" -nodes \
  -extensions v3_ca \
  -key subCA.key -sha256 -days 1024 -out subCA.pem

echo ">> Intermediate CA sign by RootCA"

cat <<EOF > ca_config.cfg
[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = critical,CA:true
EOF
openssl x509 -x509toreq -days 365 -in subCA.pem -signkey subCA.key -out subCA.req
openssl x509 -req -in subCA.req \
  -days 500 -sha256 \
  -CA rootCA.pem -CAkey rootCA.key -CAcreateserial \
  -extfile ca_config.cfg \
  -extensions v3_ca \
  -out bundleCA.crt

echo ">> Verify Intermediate CA"
openssl verify -CAfile rootCA.pem bundleCA.crt
openssl x509 -in bundleCA.crt -noout -purpose


echo ">> SSL listen certificates"
openssl req -subj "/CN=$DOMAIN"  -newkey rsa:4096 -nodes \
		-sha256 \
		-days 3650 \
		-keyout $DOMAIN.key \
		-out $DOMAIN.csr
openssl x509 -req -in $DOMAIN.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out $DOMAIN.crt -days 500 -sha256


echo ">> SSL create client cert"
openssl genrsa -out client.key 4096
openssl req -new -subj '/CN=test' -key client.key -out client.req
openssl x509 -req -in client.req \
  -CA bundleCA.crt -CAkey subCA.key \
  -CAcreateserial -out client.crt \
  -days 500 -sha256

cat client.crt bundleCA.crt rootCA.pem > client_bundle.crt
