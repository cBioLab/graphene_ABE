TOPDIR:= ../..

SSL_INCLUDE = -L/usr/local/lib
SSL_LDFLAGS = -Wall -O2 -std=c++11 -lssl -lcrypto

ABE_CFLAGS = -I/usr/local/include/openabe -O2 -std=c++11 -DSSL_LIB_INIT -fPIC -DGTEST_USE_OWN_TR1_TUPLE=0 -pthread -Wall -fstrict-overflow -Wsign-compare
ABE_INCLUDE = -L/deps/root/lib -L/root/lib -L/usr/local/lib
ABE_LDFLAGS = -lrelic -lrelic_ec -lssl -lcrypto
OPENABE_LIB = $(TOPDIR)/Runtime/libopenabe.a

SIGN = $(TOPDIR)/Runtime/pal-sgx-sign
ENCLAVE_KEY = $(TOPDIR)/Runtime/enclave-key.pem
TOKEN = $(TOPDIR)/Runtime/pal-sgx-get-token
SGX.so = $(TOPDIR)/Runtime/libpal-Linux-SGX.so

ifneq ($(JSON11_ENABLE_DR1467_CANARY),)
CANARY_ARGS = -DJSON11_ENABLE_DR1467_CANARY=$(JSON11_ENABLE_DR1467_CANARY)
endif
JSON_CFLAGS = -O2 -std=c++11 -fno-rtti -fno-exceptions

OTHERS_LDFLAGS = -lmysqlcppconn

.PHONY: all clean manifest compile server getData

all: getData

clean:
		rm -rf *.o *~ getData server manifest *.manifest.sgx *.sig *.token *.pem *.cpabe exec_time.log

manifest:
		python makeManifest.py

compile: manifest server

SGXserver:
		sudo ./$(TOPDIR)/Runtime/pal_loader SGX server


server: SSLserver.o common.o json11.o server.o
		$(CXX) -o $@ $^ $(ABE_INCLUDE) $(OPENABE_LIB) $(ABE_LDFLAGS) $(OTHERS_LDFLAGS)
		$(SIGN) -output $@.manifest.sgx -exec $@ -key $(ENCLAVE_KEY) -libpal $(SGX.so) -manifest manifest
		$(TOKEN) -output $@.token -sig $@.sig

SSLserver.o: SSLserver.cpp SSLserver.hpp
		$(CXX) -O2 -std=c++11 -Wall -c $*.cpp

common.o: common.cpp
		$(CXX) $(ABE_CFLAGS) -c $<

server.o: server.cpp SSLserver.hpp common.h
		$(CXX) $(OTHERS_LDFLAGS) $(ABE_CFLAGS) -c $<

json11.o: json11.cpp json11.hpp
		$(CXX) $(CANARY_ARGS) $(JSON_CFLAGS) -c $<


getData: SSLserver.o common.o json11.o getData.o
		$(CXX) -o $@ $^ $(ABE_INCLUDE) $(OPENABE_LIB) $(ABE_LDFLAGS) $(OTHERS_LDFLAGS)

getData.o: getData.cpp SSLserver.hpp common.h
		$(CXX) $(ABE_CFLAGS) -c $< $(OTHERS_LDFLAGS)

