#FILENAME :=  $(patsubst %.Test.cpp,%.core.test,$(wildcard core.tests/*.Test.cpp))

# openssl
OPENSSL_PATH=../build/openssl
# src
SRC_PATH=../src
# ecc
ECC_PATH=../src/ecc

all:
	@echo "please type 'make test'"

test: clean src.test  run_src_test
	@echo "Executed tests"
	
src.test : src.Test.cpp
	@echo "printing library pack for openssl .a and cryptopp .a"
	ls $(OPENSSL_PATH)/liblinux-openssl-crypto-x86_64*
	ls ../thirdparty/cryptopp/libcryptopp.a
	g++ -DCATCH_CONFIG_MAIN --coverage -g -O0 --std=c++11 -I$(SRC_PATH) -I../thirdparty -I$(OPENSSL_PATH)/include -pthread $< -o $@ $(SRC_PATH)/CryptoNeoOpenSSL.cpp $(SRC_PATH)/CryptoExtra.cpp ../thirdparty/cryptopp/libcryptopp.a  -L$(OPENSSL_PATH) -llinux-openssl-crypto-x86_64 -ldl

run_src_test: src.test
	@echo "Starting tests..."
	./src.test

.PHONY: src.test

test-coverage:
	mkdir -p reports
	lcov --directory . --capture --output-file reports/app.info
	(cd reports && genhtml app.info)

# cleaning tests
clean:
	rm -f *.test
	rm -f *.gcda
	rm -f *.gcno
	rm -f *.info
