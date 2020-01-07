#include <iostream>
#include <string>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/applink.c>
#include <WinSock2.h>
#include <windows.h>

void handleErrors(void);
int encrypt(unsigned char* plainText, int plainTextLen, unsigned char* key, unsigned char* iv, unsigned char* cipherText);
int decrypt(unsigned char* cipherText, int cipherTextLen, unsigned char* key, unsigned char* iv, unsigned char* plainText);

int main()
{
	//Set up the key and IV
	unsigned char* key = (unsigned char*) "01234567890123456789012345678901";
	unsigned char* iv = (unsigned char*)"0123456789012345";

	//Message to be encrypted and decrypted
	unsigned char* plainText = (unsigned char*)"The quick brown fox jumped over the lazy dog.";

	//Buffer for the cipher text
	unsigned char cipherText[128];

	//Buffer for the decrypted text
	unsigned char decryptedText[128];

	int encrypted_len, decrypted_len;

	//Encrypt the plain text
	encrypted_len = encrypt(plainText, strlen((char*)plainText), key, iv, cipherText);

	std::cout << "Cipher text is: " << std::endl;
	BIO_dump_fp(stdout, (const char*)cipherText, encrypted_len);
	std::cout << std::endl;

	//Now decrypt
	decrypted_len = decrypt(cipherText, encrypted_len, key, iv, decryptedText);

	std::cout << "Decrypted text is: " << std::endl;
	BIO_dump_fp(stdout, (const char*)decryptedText, decrypted_len);
	std::cout << std::endl;

	return 0;
}

void handleErrors()
{
	ERR_print_errors_fp(stdout);
	abort();
}

int encrypt(unsigned char* plainText, int plainTextLen, unsigned char* key, unsigned char* iv, unsigned char* cipherText)
{
	EVP_CIPHER_CTX* ctx;
	int len;
	int cipherText_len;

	//Create and initialize new cipher context
	if (!(ctx = EVP_CIPHER_CTX_new()))
	{
		handleErrors();
	}

	//Initialize the encryption operation
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
	{
		handleErrors();
	}

	//Provide the plain text to be encrypted and obtain the cipher text
	if (1 != EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainTextLen))
	{
		handleErrors();
	}

	cipherText_len = len;

	//Finalize the encryption
	if (1 != EVP_EncryptFinal_ex(ctx, cipherText + len, &len))
	{
		handleErrors();
	}

	cipherText_len += len;

	//Clean up
	EVP_CIPHER_CTX_free(ctx);

	return cipherText_len;
}

int decrypt(unsigned char* cipherText, int cipherTextLen, unsigned char* key, unsigned char* iv, unsigned char* plainText)
{
	EVP_CIPHER_CTX* ctx;
	int decrypted_len;
	int len;

	//Create and initialize the decryption context
	if (!(ctx = EVP_CIPHER_CTX_new()))
	{
		handleErrors();
	}

	//Initialize the decryption operation
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
	{
		handleErrors();
	}

	//Provide the cipher text to be decrypted and obtain the original plain text (hopefully)
	if (1 != EVP_DecryptUpdate(ctx, plainText, &len, cipherText, cipherTextLen))
	{
		handleErrors();
	}

	decrypted_len = len;

	//Finalize the process
	if (1 != EVP_DecryptFinal_ex(ctx, plainText + len, &len))
	{
		handleErrors();
	}

	decrypted_len += len;

	//Clean up
	EVP_CIPHER_CTX_free(ctx);

	return decrypted_len;
}