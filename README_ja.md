# graphene_ABE
属性ベース暗号とIntel SGXを用いたデータ分析プラットフォーム

# 概要
graphene_ABEは
''属性ベース暗号とIntel SGXを用いた堅牢かつ柔軟なアクセス制御を実現するデータ分析プラットフォームの構築''
の再現ソースコードである．

属性ベース暗号によってデータを暗号化して保管し，
サーバーが分析リクエストを受けると，
ユーザーの権限に合致するデータのみを
Intel SGXの提供する保護領域内で復号化して
必要な分析を行う．

# 動作確認環境
+ Intel Core(TM) i7-7700K CPU @ 4.20GHz
+ 64-bit Linux (tested on Ubuntu 16.04.6LTS)

# インストール方法
+ graphene_ABEをインストールする．

```
git clone https://github.com/cBioLab/graphene_ABE.git
git submodule update --init --recursive
```

+ 提案システムで使用するライブラリ（OpenABE，graphene）をビルドする．

## OpenABE
インストール詳細等は[こちら](https://github.com/zeutro/openabe)を参照されたい．
ここでは簡易方法について解説する．

```
cd [PATH]/graphene_ABE
cd openabe
sudo -E ./deps/install_pkgs.sh
. ./env
make
make test
sudo -E make install
```

+ 動作確認(任意)
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
インストール詳細等は[こちら](https://github.com/zeutro/openabe)を参照されたい．
ここでは簡易方法について解説する．

```
cd [PATH]/graphene_ABE
cd graphene
git submodule update --init
sudo make
cd Pal/src/host/Linux-SGX/signer/
openssl genrsa -3 -out enclave-key.pem 3072
cd ../sgx-driver
make  ☆
sudo ./load.sh
cd ../../../../../
sudo make SGX=1
```

☆: 入力を求められる．SGX driverのディレクトリとバージョンを以下のように入力する．

```
Enter the Intel SGX driver directory: ../../../../../../ABE_graphene/linux-sgx-driver
Enter the driver version (default: 1.9): 2.8
```

+ 動作確認（C++）
```
cd [PATH]/graphene_ABE/graphene/LibOS/shim/test/native/
make SGX_RUN=1
sudo ./pal_loader SGX helloworld
```


## 独自認証局の作成
```
cd [PATH]/graphene_ABE/Framework/Authority
sudo /usr/lib/ssl/misc/CA.pl -newca
```

ここで幾つか入力事項がある．以下に入力例を示す．
```
CA certificate filename (or enter to create)
> [Enter](何も入力しない) 
Making CA certificate ...
Generating a 2048 bit RSA private key
...................................................+++
...............................................................................................................................+++
writing new private key to './cakey.pem'
Enter PEM pass phrase: CAのプライベートキーファイル用のパスフェーズを入力
> password[Enter](本手法では．コードを変更すればここも任意に変更できる．)
Verifying - Enter PEM pass phrase: 
> password[Enter] 
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) []: 
> 任意で入力[Enter] 
State or Province Name (full name) []:
> 任意で入力[Enter] 
Locality Name (eg, city) []:
> 任意で入力[Enter] 
Organization Name (eg, company) []:
> 任意で入力[Enter] 
Organizational Unit Name (eg, section) []:
> 任意で入力[Enter] 
Common Name (eg, your name or your server's hostname) []:
> localhost[Enter] (もしくはドメイン名にする)
Email Address []:
> 任意で入力[Enter] 

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
> 任意で入力[Enter] 
An optional company name []:
> 任意で入力[Enter] 
Using configuration from [PATH to openssl.cnf]/openssl.cnf
Enter pass phrase for ./cakey.pem: 
> password[Enter] 
```

## 証明書の作成
### DH parameter の生成
```
cd [PATH]/graphene_ABE/Framework/Authority
[ -f dhp.pem ] || openssl genpkey -genparam -algorithm DH -pkeyopt dh_paramgen_prime_len:1024 -out dh1024.pem
```

### ルート証明書，各エンティティ証明書生成
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

上記で，鍵生成時，証明書作成時に各種入力が必要になる．
server.pem作成を例にとって説明する．
client.pem，DataOwner作成時も同様に入力する．

+ openssl genrsa -des3 2048 > server.pem
```
Generating RSA private key, 2048 bit long modulus (2 primes)
...........................................................+++
.....................................................................................................................................................................................+++
e is 65537 (0x010001)
Enter pass phrase:
> password[Enter](本手法では．コードを変更すればここも任意に変更できる．)
Verifying - Enter pass phrase:
> password[Enter]
```

+ openssl req -new -key server.pem -out server.csr
```
Enter pass phrase for server.pem:
> password[Enter]
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) []:
> CAと同じものを入力する[Enter] 
State or Province Name (full name) []:
> CAと同じものを入力する[Enter]
Locality Name (eg, city) []:
> CAと同じものを入力する[Enter]
Organization Name (eg, company) []:
> CAと同じものを入力する[Enter]
Organizational Unit Name (eg, section) []:
> 新規で入力する)[Enter]
Common Name (e.g. server FQDN or YOUR name) []:
> localhost[Enter]
Email Address []:
> 任意で入力[Enter]

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
```










# Copyright(要確認)
Copyright (C) 2019, Daiki Iwata All rights reserved.

# License(要確認)
graphene_ABEは[BSD 3-Clause License](https://opensource.org/licenses/BSD-3-Clause)である．

詳細は[License.txt](/License.txt)を参照されたい．


## 外部ライブラリのライセンス
外部ライブラリのライセンスは以下の通りである．詳細はライブラリ名のリンクから参照できる．

+ [graphene](https://github.com/oscarlab/graphene/blob/f30f7e7575befce6375783fa424a9ac6c8faa605/LICENSE.txt): GNU Lesser General Public License v3.0

+ [OpenABE](https://github.com/zeutro/openabe/blob/c0c7a2a0e2e1fb802e69cb32361f25120a46d48d/LICENSE): GNU Affero General Public License v3.0

+ [linux-sgx](https://github.com/intel/linux-sgx/blob/4230bbfb08c682aadd57680d564e36cdeda9a06a/License.txt): BSD 3-Clause License

+ [linux-sgx-driver](https://github.com/intel/linux-sgx-driver/blob/0b76a7c905b8293ef18414bd3a3a867059a1ceb6/License.txt): BSD 3-Clause License


# History
+ April 24, 2019; initial version.

# Author
岩田大輝 IWATA Daiki (d_iwata@ruri.waseda.jp)