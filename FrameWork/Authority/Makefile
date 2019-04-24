TOPDIR:= ../..

ABE_CFLAGS = -I/usr/local/include/openabe -O2 -std=c++11 -DSSL_LIB_INIT -fPIC -DGTEST_USE_OWN_TR1_TUPLE=0 -pthread -Wall -fstrict-overflow -Wsign-compare
ABE_INCLUDE = -L/deps/root/lib -L/root/lib -L/usr/local/lib
ABE_LDFLAGS = -lrelic -lrelic_ec -lssl -lcrypto
OPENABE_LIB = $(TOPDIR)/Runtime/libopenabe.a

SIGN = $(TOPDIR)/Runtime/pal-sgx-sign
ENCLAVE_KEY = $(TOPDIR)/Runtime/enclave-key.pem
TOKEN = $(TOPDIR)/Runtime/pal-sgx-get-token
SGX.so = $(TOPDIR)/Runtime/libpal-Linux-SGX.so

ABE_files = setup keygen

.PHONY: all setup keygen clean

%.o: %.cpp
		$(CXX) $(ABE_CFLAGS) -c $<

all: $(ABE_files)

clean:
		rm -rf *.o *~ $(ABE_files) *.manifest.sgx *.sig *.token *.cpabe *.key

setup: common.o setup.o
		$(CXX) -o $@ $^ $(ABE_CFLAGS) $(ABE_INCLUDE) $(OPENABE_LIB) $(ABE_LDFLAGS)
		$(SIGN) -output $@.manifest.sgx -exec $@ -key $(ENCLAVE_KEY) -libpal $(SGX.so) -manifest manifest
		$(TOKEN) -output $@.token -sig $@.sig

keygen: common.o keygen.o
		$(CXX) -o $@ $^ $(ABE_CFLAGS) $(ABE_INCLUDE) $(OPENABE_LIB) $(ABE_LDFLAGS)
		$(SIGN) -output $@.manifest.sgx -exec $@ -key $(ENCLAVE_KEY) -libpal $(SGX.so) -manifest manifest
		$(TOKEN) -output $@.token -sig $@.sig

SGX_ABEsetting:
		sudo ./../../Runtime/pal_loader SGX setup -s CP
		sudo ./../../Runtime/pal_loader SGX keygen -s CP -i \
		"sysadmin | it_depertment | president | iwata | daiki | notebook | pencil | mouse | cat | dog" \
				-o sample.key
		cp root.pem server.pem dh1024.pem mpk.cpabe ../server
		cp root.pem client.pem mpk.cpabe sample.key ../client
		cp root.pem DataOwner.pem mpk.cpabe ../DataOwner
