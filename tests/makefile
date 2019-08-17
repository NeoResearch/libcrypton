#FILENAME :=  $(patsubst %.Test.cpp,%.core.test,$(wildcard core.tests/*.Test.cpp))

# openssl
OPENSSL_PATH=../build/openssl
# src
SRC_PATH=../src
# ecc
ECC_PATH=../src/ecc
# gtest
GTEST_PATH=../libgtest/build/googletest
GMOCK_PATH=../libgtest/build/googlemock
GTEST_INCLUDE=../libgtest/googletest/include
GMOCK_INCLUDE=../libgtest/googlemock/include

all:
	@echo "please type 'make test'"

test: clean src.test 
	@echo "Executed tests"
	./src.test

src.test : src.Test.cpp
	g++ --coverage -g -O0 --std=c++11 -I$(SRC_PATH) -I$(GTEST_INCLUDE) -I$(GMOCK_INCLUDE) -I$(OPENSSL_PATH)/include -pthread $< -o $@ $(GMOCK_PATH)/gtest/libgtest_main.a $(GMOCK_PATH)/gtest/libgtest.a $(GMOCK_PATH)/libgmock.a $(SRC_PATH)/CryptoNeoOpenSSL.cpp $(SRC_PATH)/CryptoExtra.cpp $(SRC_PATH)/cryptopp/libcryptopp.a  -L$(OPENSSL_PATH) -llinux-openssl-crypto-x86_64 -lpthread -ldl


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
