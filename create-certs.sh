echo "*****************  Certs creation  *************************"

function echo {
  COLOR="\e[93m";
  ENDCOLOR="\e[0m";
  printf "$COLOR%b$ENDCOLOR\n" "$1";
}

export CERT_FOLDER="$(pwd)/certs"
export DOMAIN="test.com"

mkdir -p $CERT_FOLDER
rm $CERT_FOLDER/*
cd $CERT_FOLDER

echo "Certs creation on folder: $CERT_FOLDER"

echo ">> SSL create CA cert"
openssl genrsa -out rootCA.key 2048
openssl req -batch -new -x509 -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.pem

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
  -CA rootCA.pem -CAkey rootCA.key \
  -CAcreateserial -out client.crt \
  -days 500 -sha256
