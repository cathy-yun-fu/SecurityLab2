#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "lib/sha1.h"

char IPAD[SHA1_BLOCKSIZE];
char OPAD[SHA1_BLOCKSIZE];

uint8_t innerSHA[SHA1_BLOCKSIZE];
uint8_t outerSHA[SHA1_BLOCKSIZE];

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


void base2SecretKey(const char* secret_hex, uint8_t* secretkey){
	int j = 0; //index into output
	int length = strlen(secret_hex);
	int i =0;
	for (i = 0; i < length; i+=2){
		int a = getInt(secret_hex[i]);
		int b = getInt(secret_hex[i+1]);
		secretkey[j] = (a << 4) + b; // a*2^4 + b -> left 4 bits are a
		j = j +1;
	}
}


void initializeHMAC(char* secret_hex){
	uint8_t secretKey[10];
	base2SecretKey(secret_hex, secretKey); // base 2

	uint8_t padded_key[SHA1_BLOCKSIZE];
	int i = 0;
	for (i = 0; i < 10; i++){
		padded_key[i] = secretKey[i];
	}
	for (i = 10; i < SHA1_BLOCKSIZE; i++){
		padded_key[i] = 0;
	}

	// IPAD , OPAD initialized
	for (i = 0; i < SHA1_BLOCKSIZE; i++) {
		IPAD[i] = '\x36';
		OPAD[i] = '\x5c';
	}

	// KEY ^ IPAD
	for (i = 0; i < SHA1_BLOCKSIZE; i++){
		innerSHA[i] = padded_key[i]^IPAD[i];
	}

	// KEY ^ OPAD
	for (i = 0; i < SHA1_BLOCKSIZE; i++){
		outerSHA[i] = padded_key[i]^OPAD[i];
	}
}

void computeHMAC(int step_value, uint8_t* shaOutput){
	SHA1_INFO  ctx;

	// INNER =====
	// has to be 8
//	uint8_t data_value[8];
//	data_value[7] = step_value & 0x000000ff;
//	data_value[6] = step_value & 0x0000ff00;
//	data_value[5] = step_value & 0x00ff0000;
//	data_value[4] = step_value & 0xff000000;
//	data_value[3] = 0;
//	data_value[2] = 0;
//	data_value[1] = 0;
//	data_value[0] = 0;
  	uint8_t data_value[8];
	data_value[7] = 0x01;
	data_value[6] = 0;
	data_value[5] = 0;
	data_value[4] = 0;
	data_value[3] = 0;
	data_value[2] = 0;
	data_value[1] = 0;
	data_value[0] = 0;

	uint8_t shaInnerOutput[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx);
	sha1_update(&ctx, innerSHA, SHA1_BLOCKSIZE);
	sha1_update(&ctx, data_value, 8);
	sha1_final(&ctx, shaInnerOutput);

	// OUTER =====
	sha1_init(&ctx);
	sha1_update(&ctx, outerSHA, SHA1_BLOCKSIZE);
	sha1_update(&ctx, shaInnerOutput,20);
	sha1_final(&ctx, shaOutput);
}


int DynamicTruncate(uint8_t* shaOutput) {
	uint8_t index = shaOutput[19] & 0xf;
	int value = ( (shaOutput[index] & 0x7f) << 24 )
							| ((shaOutput[index+1] & 0xff) << 16)
							| ((shaOutput[index+2] & 0xff) << 8)
							| (shaOutput[index+3] & 0xff);
//	int i=0;
//	for (i = 0; i < 20; i++){
//		printf(" %d %d |",(shaOutput[i] & 0xf0) >> 4, (shaOutput[i] & 0x0f));
//	}
//	printf("\n");
//	printf("debug: %d, %d\n", index, value);
	return (value % 1000000); // 10^6
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	int HOTP_input = atoi(HOTP_string);
//	printf("Input HOTP: %d\n", HOTP_input);

	int i = 1; // initial counter value
	uint8_t shaOutput[SHA1_DIGEST_LENGTH];
	computeHMAC(1,shaOutput);

	int output = DynamicTruncate(shaOutput);

	return (output == atoi(HOTP_string));

//
//	for (i = 1; i <= 5; i++) {
//		uint8_t shaOutput[SHA1_DIGEST_LENGTH];
//		computeHMAC(i, shaOutput);
//		int HOTP = DynamicTruncate(shaOutput);
////		printf("Counter: %d HOTP: %d \n\n", i, HOTP);
//		if (HOTP == HOTP_input) {
//			return 1;
//		}
//	}
//
//	return (0);
}

static int
validateTOTPhelper(uint8_t * secret_hex, char * HOTP_string, int t)
{
	int i;
	uint8_t in_data[8];
	for( i = 7; i >= 0 ; i--){
		in_data[i] = t & 0xff;
		t >>= 8;
	}

	uint8_t shaOutput[SHA1_DIGEST_LENGTH];
	SHA1_INFO  ctx;
	uint8_t shaInnerOutput[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx);
	sha1_update(&ctx, innerSHA, SHA1_BLOCKSIZE);
	sha1_update(&ctx, in_data, 8);
	sha1_final(&ctx, shaInnerOutput);

	// OUTER =====
	sha1_init(&ctx);
	sha1_update(&ctx, outerSHA, SHA1_BLOCKSIZE);
	sha1_update(&ctx, shaInnerOutput,20);
	sha1_final(&ctx, shaOutput);

	int output = DynamicTruncate(shaOutput);

	return (output == atoi(HOTP_string));
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	int TOTP_input = atoi(TOTP_string);

	int period = 30;
	int timer = (time(NULL)) / period;

	initializeHMAC(secret_hex);
	return validateTOTPhelper(secret_hex, TOTP_string, timer);
}

int
main(int argc, char * argv[]) {
	if (argc != 4) {
		printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
		return (-1);
	}

	char *secret_hex = argv[1];
	char *HOTP_value = argv[2];
	char *TOTP_value = argv[3];

	assert(strlen(secret_hex) <= 20);
	assert(strlen(HOTP_value) == 6);
	assert(strlen(TOTP_value) == 6);

	initializeHMAC(secret_hex);

	long n = time(NULL);
	printf("time is %ld\n" , n);
	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
				 secret_hex,
				 HOTP_value,
				 validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
				 TOTP_value,
				 validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");
}
