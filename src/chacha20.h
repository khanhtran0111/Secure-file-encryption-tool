#ifndef CHACHA20_H
#define CHACHA20_H

#include <cstdint>
#include <vector>

extern "C" {
    void encrypt(const uint8_t* key, const uint8_t* nonce, const uint8_t* plaintext, size_t length, uint8_t* ciphertext);
    void decrypt(const uint8_t* key, const uint8_t* nonce, const uint8_t* ciphertext, size_t length, uint8_t* plaintext);
}

#endif