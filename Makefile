# openssl
OPENSSL_PATH=./build/openssl
# src
SRC_PATH=./src


all: bin/crypdev

bin/crypdev: src/crypdev.cpp src/ModuleCryptoDev.hpp
	g++ -Ofast --std=c++17 -I$(SRC_PATH) -I$(OPENSSL_PATH)/include -pthread $< -o  $@  $(SRC_PATH)/CryptoNeoOpenSSL.cpp  -L$(OPENSSL_PATH) -llinux-openssl-crypto-x86_64 -lpthread -ldl
	g++ -Ofast --std=c++17 -I$(SRC_PATH) -I$(OPENSSL_PATH)/include -pthread $< -o  extra$@  $(SRC_PATH)/CryptoNeoOpenSSL.cpp $(SRC_PATH)/CryptoExtra.cpp $(SRC_PATH)/cryptopp/libcryptopp.a  -L$(OPENSSL_PATH) -llinux-openssl-crypto-x86_64 -lpthread -ldl

vendor: openssl cryptopp #clang gtests

openssl:
	#cd src/core && chmod +x linux_get_build_openssl.sh
	#cd src/core && ./linux_get_build_openssl.sh
	mkdir -p build/openssl
	(cd build/openssl && ../../libopenssl/config && make && make test)
	cp -r libopenssl/include build/openssl/   # include files
	cp build/openssl/libcrypto.a build/openssl/liblinux-openssl-crypto-x86_64.a
	#cp -r build/openssl/include/openssl/* build/openssl/include/openssl/
	#mv tmp_build/libcrypto.a crypto/openssl/liblinux-openssl-crypto-x86_64.a

cryptopp:
	cd thirdparty/cryptopp/ && make
