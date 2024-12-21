#include<bits/stdc++.h>
using namespace std;

class ChaCha20 {
public:
    ChaCha20(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter = 0) {
        // Initialize the state
        state[0] = CONSTANTS[0];
        state[1] = CONSTANTS[1];
        state[2] = CONSTANTS[2];
        state[3] = CONSTANTS[3];

        // Copy the 256-bit key into the state
        for (int i = 0; i < 8; ++i) {
            state[4 + i] = toUint32(key + i * 4);
        }

        // Set the counter and nonce
        state[12] = counter;
        for (int i = 0; i < 3; ++i) {
            state[13 + i] = toUint32(nonce + i * 4);
        }
    }

    void encrypt(const vector<uint8_t>& plaintext, vector<uint8_t>& ciphertext) {
        process(plaintext, ciphertext);
    }

    void decrypt(const vector<uint8_t>& ciphertext, vector<uint8_t>& plaintext) {
        process(ciphertext, plaintext);
    }

private:
    uint32_t state[16];
    static const uint32_t CONSTANTS[4];

    uint32_t toUint32(const uint8_t* bytes) {
        return (uint32_t(bytes[0]) | (uint32_t(bytes[1]) << 8) | (uint32_t(bytes[2]) << 16) | (uint32_t(bytes[3]) << 24));
    }

    void toBytes(uint32_t value, uint8_t* bytes) {
        bytes[0] = value & 0xFF;
        bytes[1] = (value >> 8) & 0xFF;
        bytes[2] = (value >> 16) & 0xFF;
        bytes[3] = (value >> 24) & 0xFF;
    }

    void process(const vector<uint8_t>& input, vector<uint8_t>& output) {
        output.resize(input.size());
        vector<uint8_t> keystream(64);
        uint32_t block[16];
        size_t offset = 0;

        #define ROTATE(v, c) (((v) << (c)) | ((v) >> (32 - (c))))
        #define QR(a, b, c, d) \
            a += b; d ^= a; d = ROTATE(d, 16); \
            c += d; b ^= c; b = ROTATE(b, 12); \
            a += b; d ^= a; d = ROTATE(d, 8);  \
            c += d; b ^= c; b = ROTATE(b, 7);

        while (offset < input.size()) {
            // Generate the keystream block
            memcpy(block, state, sizeof(state));
            for (int i = 0; i < 10; ++i) {
                QR(block[0], block[4], block[8], block[12]);
                QR(block[1], block[5], block[9], block[13]);
                QR(block[2], block[6], block[10], block[14]);
                QR(block[3], block[7], block[11], block[15]);

                QR(block[0], block[5], block[10], block[15]);
                QR(block[1], block[6], block[11], block[12]);
                QR(block[2], block[7], block[8], block[13]);
                QR(block[3], block[4], block[9], block[14]);
            }

            for (int i = 0; i < 16; ++i) {
                block[i] += state[i];
                keystream[i * 4 + 0] = block[i] & 0xFF;
                keystream[i * 4 + 1] = (block[i] >> 8) & 0xFF;
                keystream[i * 4 + 2] = (block[i] >> 16) & 0xFF;
                keystream[i * 4 + 3] = (block[i] >> 24) & 0xFF;
            }

            size_t bytesToProcess = min<size_t>(64, input.size() - offset);
            for (size_t i = 0; i < bytesToProcess; ++i) {
                output[offset + i] = input[offset + i] ^ keystream[i];
            }

            ++state[12];
            offset += bytesToProcess;
        }
    }
};

const uint32_t ChaCha20::CONSTANTS[4] = {0x61707865, 0x3320646E, 0x79622D32, 0x6B206574};

extern "C" {
    void encrypt(const uint8_t* key, const uint8_t* nonce, const uint8_t* plaintext, size_t plaintext_len, uint8_t* ciphertext) {
        ChaCha20 chacha(key, nonce);
        vector<uint8_t> pt(plaintext, plaintext + plaintext_len);
        vector<uint8_t> ct;
        chacha.encrypt(pt, ct);
        memcpy(ciphertext, ct.data(), ct.size());
    }

    void decrypt(const uint8_t* key, const uint8_t* nonce, const uint8_t* ciphertext, size_t ciphertext_len, uint8_t* plaintext) {
        ChaCha20 chacha(key, nonce);
        vector<uint8_t> ct(ciphertext, ciphertext + ciphertext_len);
        vector<uint8_t> pt;
        chacha.decrypt(ct, pt);
        memcpy(plaintext, pt.data(), pt.size());
    }
}