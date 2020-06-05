# openssl
OPENSSL_PATH=./build/openssl
# src
SRC_PATH=./src

TP_PATH=./thirdparty

all: bin/crypdev

bin/crypdev: src/crypdev.cpp src/ModuleCryptoDev.hpp ./thirdparty/cryptopp/libcryptopp.a
	g++ -Ofast --std=c++17 -I$(SRC_PATH) -I$(OPENSSL_PATH)/include -pthread $< -o  $@  $(SRC_PATH)/CryptoNeoOpenSSL.cpp  -L$(OPENSSL_PATH) -llinux-openssl-crypto-x86_64 -lpthread -ldl
	g++ -Ofast --std=c++17 -I$(SRC_PATH) -I$(OPENSSL_PATH)/include -I$(TP_PATH) -pthread $< -o  $@-extra  $(SRC_PATH)/CryptoNeoOpenSSL.cpp $(SRC_PATH)/CryptoExtra.cpp $(TP_PATH)/cryptopp/libcryptopp.a  -L$(OPENSSL_PATH) -llinux-openssl-crypto-x86_64 -lpthread -ldl

vendor: get_submodules openssl cryptopp #clang gtests

get_submodules:
	git submodule update --init --recursive
	git submodule update --recursive

openssl:
ifeq (,$(wildcard ./build/openssl/liblinux-openssl-crypto-x86_64.a))
	@echo "OpenSSL needs to be built"
	rm -rf build/openssl/
	mkdir -p build/openssl
	(cd build/openssl && ../../libopenssl/config && make && make test)
	cp -r libopenssl/include build/openssl/   # include files
	cp build/openssl/libcrypto.a build/openssl/liblinux-openssl-crypto-x86_64.a
else
	@echo "OpenSSL library already exists! ./build/openssl/liblinux-openssl-crypto-x86_64.a"
endif
	@echo "=========== Finished OpenSSL ==========="

cryptopp:
	cd thirdparty/cryptopp/ && make
	@echo "=========== Finished Crypto++ ==========="

test:
	cd tests && make test

clean:
	rm -f bin/crypdev

old_openssl:
	#cd src/core && chmod +x linux_get_build_openssl.sh
	#cd src/core && ./linux_get_build_openssl.sh
	mkdir -p build/openssl
	(cd build/openssl && ../../libopenssl/config && make && make test)
	cp -r libopenssl/include build/openssl/   # include files
	cp build/openssl/libcrypto.a build/openssl/liblinux-openssl-crypto-x86_64.a
	#cp -r build/openssl/include/openssl/* build/openssl/include/openssl/
	#mv tmp_build/libcrypto.a crypto/openssl/liblinux-openssl-crypto-x86_64.a
