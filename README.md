# graphene_ABE
Data Mining PlatformUsing Attribute-Based Encryption and Intel SGX.

README in Japanese is [here](/README_ja.md).

# Summary
graphene_ABE is the test codes of the study, 
''Secure and Fine-Grained Accessible Data Mining PlatformUsing Attribute-Based Encryption and Intel SGX''.

In our system, all the data is encrypted by the ABE. 
When the server receives a request from auser, 
only the subset of data that the user is authorized to access 
is decrypted and analyzed in the enclave
(a secure region provided by Intel SGX), 
and only the result is returned to the user.


# Supported CPU and Operating Systems
+ Intel Core(TM) i7-7700K CPU @ 4.20GHz
+ 64-bit Linux (tested on Ubuntu 16.04.6LTS)

# Installation
Create a working directory (e.g., work) and 
clone repositories.
```
cd ~
mkdir work
cd work
git clone https://github.com/cBioLab/graphene_ABE.git
git submodule update --init --recursive
```

## OpenABE
To use graphene_ABE, build OpenABE library at first. 
To get more information about OpenABE installation, check [here](https://github.com/oscarlab/graphene/tree/f30f7e7575befce6375783fa424a9ac6c8faa605).

```
cd [PATH]/graphene_ABE
cd openabe
sudo -E ./deps/install_pkgs.sh
. ./env
make
make test
sudo -E make install
```

+ OPTIONAL  
    To compile and execute C++ test apps that use the high-level OpenABE crypto box API, do as follows.
```
cd [PATH]/graphene_ABE/openabe
make examples
cd examples
./test_kp
./test_cp
./test_pk
./test_km
```


## graphene
To use graphene_ABE, build graphene library. 
To get more information about graphene installation, check [here](https://github.com/zeutro/openabe/tree/c0c7a2a0e2e1fb802e69cb32361f25120a46d48d).

```
cd [PATH]/graphene_ABE
cd graphene
git submodule update --init
sudo make
cd Pal/src/host/Linux-SGX/signer/
openssl genrsa -3 -out enclave-key.pem 3072
cd ../sgx-driver
make
sudo ./load.sh
cd ../../../../../
sudo make SGX=1
```


+ OPTIONAL  
    To compile and execute C++ test codes, do as follows.

```
cd [PATH]/graphene_ABE/graphene/LibOS/shim/test/native/
make SGX_RUN=1
sudo ./pal_loader SGX helloworld
```


## Create Self Sertificate Authority
+ In this system, you need to difine the password of cakey.pem, "password". If you define your own password, modify some files...

```
cd [PATH]/graphene_ABE/Framework/Authority
sudo /usr/lib/ssl/misc/CA.pl -newca
```
## Create certificate
### Create DH parameter
```
cd [PATH]/graphene_ABE/Framework/Authority
[ -f dhp.pem ] || openssl genpkey -genparam -algorithm DH -pkeyopt dh_paramgen_prime_len:1024 -out dh1024.pem
```

### Create each certificate
```
cd [PATH]/graphene_ABE/Framework/Authority

openssl genrsa -des3 2048 > server.key
openssl req -new -key server.key -out server.csr
sudo openssl ca -out server.crt -infiles server.csr
cat server.crt server.key > server.pem
rm server.crt server.csr server.key

openssl genrsa -des3 2048 > client.key
openssl req -new -key client.key -out client.csr
sudo openssl ca -out client.crt -infiles client.csr
cat client.crt client.key > client.pem
rm client.crt client.csr client.key

openssl genrsa -des3 2048 > DataOwner.key
openssl req -new -key DataOwner.key -out DataOwner.csr
sudo openssl ca -out DataOwner.crt -infiles DataOwner.csr
cat DataOwner.crt DataOwner.key > DataOwner.pem
rm DataOwner.crt DataOwner.csr DataOwner.key

cp demoCA
cp cacert.pem ../
mv cacert.pem root.pem
```


# Quick Start
## Setup, Keygen
```
cd [PATH]/graphene_ABE/Framework
make
```

## Upload
```
@server
cd [PATH]/graphene_ABE/Framework/server
./getData

@DataOwner
cd [PATH]/graphene_ABE/Framework/DataOwner
make upload
```

## Compile
```
cd [PATH]/graphene_ABE/Framework/server
make compile
```

## Analyze
```
@server
cd [PATH]/graphene_ABE/Framework/server
make SGXserver

@client
cd [PATH]/graphene_ABE/Framework/client
make analyze
make check
```


# Copyright
Copyright (C) 2019, Daiki Iwata All rights reserved.

# License
graphene_ABE (files in this repository) is distributed under the [BSD 3-Clause License](https://opensource.org/licenses/BSD-3-Clause).

For more information, please visit [License.txt](/License.txt).


## Licenses of External Libraries
Licenses of external libraries are listed as follows.

+ [graphene](https://github.com/oscarlab/graphene/blob/f30f7e7575befce6375783fa424a9ac6c8faa605/LICENSE.txt): GNU Lesser General Public License v3.0

+ [OpenABE](https://github.com/zeutro/openabe/blob/c0c7a2a0e2e1fb802e69cb32361f25120a46d48d/LICENSE): GNU Affero General Public License v3.0

+ [linux-sgx](https://github.com/intel/linux-sgx/blob/4230bbfb08c682aadd57680d564e36cdeda9a06a/License.txt): BSD 3-Clause License

+ [linux-sgx-driver](https://github.com/intel/linux-sgx-driver/blob/0b76a7c905b8293ef18414bd3a3a867059a1ceb6/License.txt): BSD 3-Clause License


# History
+ April 24, 2019; initial version.

# Author
岩田大輝 IWATA Daiki (d_iwata@ruri.waseda.jp)