#ifndef AES_HPP
#define AES_HPP

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

/**
 * Wrapper class for Cryptopp/aes
 */
class Aes
{
	public:
		Aes(char* key, unsigned int keyLength, char* iv, unsigned int ivLength, bool encodeMode);
		virtual ~Aes();
		void encode(char* data, unsigned int length);
		void decode(char* data, unsigned int length);
	protected:
		bool encodeMode;
		CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption* encryption;
		CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption* decryption;
	private:
};

#endif
