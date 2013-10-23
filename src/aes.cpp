#include "aes.hpp"

Aes::Aes(char* key, unsigned int keyLength, char* iv, unsigned int ivLength, bool encodeMode)
{
	assert(keyLength >= CryptoPP::AES::MIN_KEYLENGTH);
	assert(keyLength <= CryptoPP::AES::MAX_KEYLENGTH);
	assert(keyLength%CryptoPP::AES::KEYLENGTH_MULTIPLE == 0);
	assert(ivLength == CryptoPP::AES::BLOCKSIZE);
	this->encodeMode = encodeMode;
	if (encodeMode)
	{
		this->encryption = new CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption((const byte*)key, keyLength, (const byte*)iv);
	}
	else
	{
		this->decryption = new CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption((const byte*)key, keyLength, (const byte*)iv);
	}
}

Aes::~Aes()
{
	if (encodeMode)
	{
		delete this->encryption;
		this->encryption = NULL;
	}
	else
	{
		delete this->decryption;
		this->decryption = NULL;
	}
}

void Aes::encode(char* data, unsigned int length)
{
	this->encryption->ProcessData((byte*)data, (const byte*)data, length);
}

void Aes::decode(char* data, unsigned int length)
{
	this->decryption->ProcessData((byte*)data, (const byte*)data, length);
}
