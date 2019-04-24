.PHONY: all clean Authority DataOwner server client clean

all: Authority DataOwner server client

Authority:
		$(MAKE) -C Authority
		sudo $(MAKE) -C Authority SGX_ABEsetting

DataOwner:
		@ cd server; mkdir -p data
		$(MAKE) -C DataOwner
		$(MAKE) -C DataOwner setup

server:
		$(MAKE) -C server

client:
		$(MAKE) -C client

clean:
		$(MAKE) -C Authority clean
		$(MAKE) -C DataOwner clean
		$(MAKE) -C server clean
		$(MAKE) -C client clean
