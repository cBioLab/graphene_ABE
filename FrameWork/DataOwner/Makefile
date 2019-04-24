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


.PHONY: all setup encrypt LogisticRegression sendData

%.o: %.cpp
		$(CXX) $(ABE_CFLAGS) -c $<

all: encrypt LogisticRegression sendData

clean:
		rm -rf *.o *~ encrypt LogisticRegression sendData *.cpabe *.pem
		@ cd BCW; rm -rf *.cpabe *.data
		@ cd RANDOM; rm -rf *.cpabe *.data
		@ cd ../server; rm -rf data

setup:
		@ cd BCW; python makeData4BCW.py
		./LogisticRegression ./BCW/train-BCW.data ./BCW/LRtheta-BCWc++.data
		./encrypt -s CP -k "mpk.cpabe" -e \
	"sysadmin and it_depertment and president and iwata and daiki and notebook and pencil and mouse and cat and dog" \
			-i ./BCW/train-BCW.data -o ./BCW/train-BCW.data.cpabe
#@ cd BCW; cp train-BCW.data.cpabe ../../server/data

upload:
		./sendData ./BCW/train-BCW.data train-BCW.data.cpabe "iwata and daiki"

encrypt: common.o encrypt.o
		$(CXX) -o $@ $^ $(ABE_INCLUDE) $(OPENABE_LIB) $(ABE_LDFLAGS)

LogisticRegression: LogisticRegression.cpp
		$(CXX) -o $@ $^ -O2 -std=c++11

sendData: SSLclient.o common.o json11.o sendData.o
		$(CXX) -o $@ $^ $(ABE_INCLUDE) $(OPENABE_LIB) $(ABE_LDFLAGS)

SSLclient.o: SSLclient.cpp SSLclient.hpp
		$(CXX) -O2 -std=c++11 -Wall -c $*.cpp

json11.o: json11.cpp json11.hpp
		$(CXX) $(CANARY_ARGS) $(JSON_CFLAGS) -c $<
