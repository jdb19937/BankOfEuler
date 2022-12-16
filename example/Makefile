HOSTNAME = localhost

all: bankserve.key.pem bankserve.cert.pem flipserve.key.pem flipserve.cert.pem

%.key.pem:
	openssl genrsa 1024 > $@
	chmod 400 $@

%.cert.pem: %.key.pem
	openssl req -nodes -new -x509 -days 365 \
		-subj '/C=US/ST=California/L=San Francisco/O=BankOfEuler/CN=$(HOSTNAME)' \
		-key $^ -out $@
	chmod 444 $@

clean:
	rm -f *.key.pem *.cert.pem *.keycert.pem
