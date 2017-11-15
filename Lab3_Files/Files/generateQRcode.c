#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

const char* HOTP = "otpauth://hotp/";
const char* TOTP = "otpauth://totp/";
const char* ISSUER_PREFIX = "?issuer=";
const char* SECRET_PREFIX = "?secret=";
const char* COUNTER = "?counter=30";
const char* PERIOD = "?period=30";

int getInt(char a){
	int temp = a;
	int value = 0;
	if (temp <=57 && temp >=48){
		value = (temp - 48);
	} else if (temp >=65 && temp <=70){
		value = (temp - 65) + 10;
	}
	return value;
}


void encodeSecretKey(const char* secret_hex, uint8_t* secretkey){
	int j = 0; //index into output
	int length = strlen(secret_hex);
	int i =0;
	for (i = 0; i < length; i+=2){
		printf("index: %d, hex chars: %c %c\n",i,secret_hex[i], secret_hex[i+1]);
		int a = getInt(secret_hex[i]);
		int b = getInt(secret_hex[i+1]);
		secretkey[j] = a*(16) + b; // a*2^4 + b -> left 4 bits are a
		printf("binary as int value: %d \n\n", secretkey[j]);
		j = j +1;
	}
}

int
main(int argc, char * argv[]) {
	if (argc != 4) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return (-1);
	}

	char *issuer = argv[1];
	char *accountName = argv[2];
	char *secret_hex = argv[3];

	assert(strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
				 issuer, accountName, secret_hex);

	const char *encoded_issuer = urlEncode(issuer);
	const char *encoded_accountName = urlEncode(accountName);

	uint8_t secretKey[10];
	encodeSecretKey(secret_hex, secretKey);

	int i = 0;
	for (i = 0; i < 10; i++) {
		printf("%d\n", secretKey[i]);
	}

	uint8_t encoded_key[20];
	base32_encode(secretKey,10,encoded_key,20);
	printf("secretkey (32 base): %s\n", encoded_key);
	printf("%d\n", strlen(encoded_key));

	// length to allocate for char* URL[]
	int shared_length = strlen(ISSUER_PREFIX) + strlen(SECRET_PREFIX)
											+ strlen(encoded_issuer) + strlen(encoded_accountName) + strlen(encoded_key);
	int length_hotp = strlen(HOTP) + shared_length + strlen(COUNTER);
	int length_totp = strlen(TOTP) + shared_length + strlen(PERIOD);

	char URL_hotp[length_hotp];
	char URL_totp[length_totp];



	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	displayQRcode("otpauth://testing");

	return (0);
}
