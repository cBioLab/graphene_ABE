TOPDIR:= ../..

SSL_INCLUDE = -L/usr/local/lib
SSL_LDFLAGS = -Wall -O2 -std=c++11 -lssl -lcrypto

ABE_CFLAGS = -I/usr/local/include/openabe -O2 -std=c++11 -DSSL_LIB_INIT -fPIC -DGTEST_USE_OWN_TR1_TUPLE=0 -pthread -Wall -fstrict-overflow -Wsign-compare
ABE_INCLUDE = -L/deps/root/lib -L/root/lib -L/usr/local/lib
ABE_LDFLAGS = -lrelic -lrelic_ec -lssl -lcrypto
OPENABE_LIB = $(TOPDIR)/Runtime/libopenabe.a

ifneq ($(JSON11_ENABLE_DR1467_CANARY),)
CANARY_ARGS = -DJSON11_ENABLE_DR1467_CANARY=$(JSON11_ENABLE_DR1467_CANARY)
endif
JSON_CFLAGS = -O2 -std=c++11 -fno-rtti -fno-exceptions


.PHONY: all clean client decrypt

all: client decrypt

clean:
		rm -rf client decrypt *.o *~ *.data *.cpabe *.pem *.key

decrypt: common.o decrypt.o
		$(CXX) -o $@ $^ $(ABE_INCLUDE) $(OPENABE_LIB) $(ABE_LDFLAGS)

common.o: common.cpp
		$(CXX) $(ABE_CFLAGS) -c $<

decrypt.o: decrypt.cpp
		$(CXX) $(ABE_CFLAGS) -c $<


client: SSLclient.o json11.o client.o
		$(CXX) -o $@ $^ $(ABE_INCLUDE) $(OPENABE_LIB) $(ABE_LDFLAGS)

SSLclient.o: SSLclient.cpp SSLclient.hpp
		$(CXX) -O2 -std=c++11 -Wall -c $*.cpp

client.o: client.cpp SSLclient.hpp
		$(CXX) $(ABE_CFLAGS) -c $<

json11.o: json11.cpp json11.hpp
		$(CXX) $(CANARY_ARGS) $(JSON_CFLAGS) -c $<


check:
		./decrypt -s CP -p ./mpk.cpabe -k ./sample.key -i ./result.data.cpabe -o ./result.data
		python analysis.py result.data ./../DataOwner/BCW/test-BCW.data

analyze:
		./client -s ./sample.key -p iwata,daiki -r result.data.cpabe -a train-BCW.data.cpabe
