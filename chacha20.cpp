#include <cstdint>
#include <vector>
#include <iostream>
#include <iomanip>
#include <cstring>
using namespace std;

// ChaCha20 Constants
const uint32_t CONSTANTS[4] = {0x61707865, 0x3320646E, 0x79622D32, 0x6B206574};

// Hàm quay vòng trái
inline uint32_t rotate(uint32_t v, uint32_t c) {
    return (v << c) | (v >> (32 - c));
}

// Hàm Quarter Round
inline void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotate(d, 16);
    c += d; b ^= c; b = rotate(b, 12);
    a += b; d ^= a; d = rotate(d, 8);
    c += d; b ^= c; b = rotate(b, 7);
}

// Khởi tạo trạng thái ChaCha20
void initializeState(uint32_t state[16], const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    // Sao chép các hằng số
    memcpy(state, CONSTANTS, sizeof(CONSTANTS));

    // Sao chép khóa (256-bit key)
    for (int i = 0; i < 8; ++i) {
        state[4 + i] = (uint32_t(key[i * 4]) | (uint32_t(key[i * 4 + 1]) << 8) |
                        (uint32_t(key[i * 4 + 2]) << 16) | (uint32_t(key[i * 4 + 3]) << 24));
    }

    // Đặt counter và nonce
    state[12] = counter;
    for (int i = 0; i < 3; ++i) {
        state[13 + i] = (uint32_t(nonce[i * 4]) | (uint32_t(nonce[i * 4 + 1]) << 8) |
                         (uint32_t(nonce[i * 4 + 2]) << 16) | (uint32_t(nonce[i * 4 + 3]) << 24));
    }
}

// Sinh keystream và mã hóa/giải mã
void chachaProcess(const uint32_t initialState[16], const vector<uint8_t>& input, vector<uint8_t>& output) {
    output.resize(input.size());
    uint32_t state[16];
    uint32_t block[16];
    vector<uint8_t> keystream(64);
    size_t offset = 0;

    memcpy(state, initialState, sizeof(state)); // Khởi tạo trạng thái

    while (offset < input.size()) {
        // Sinh keystream
        memcpy(block, state, sizeof(state));
        for (int i = 0; i < 10; ++i) {
            quarterRound(block[0], block[4], block[8], block[12]);
            quarterRound(block[1], block[5], block[9], block[13]);
            quarterRound(block[2], block[6], block[10], block[14]);
            quarterRound(block[3], block[7], block[11], block[15]);

            quarterRound(block[0], block[5], block[10], block[15]);
            quarterRound(block[1], block[6], block[11], block[12]);
            quarterRound(block[2], block[7], block[8], block[13]);
            quarterRound(block[3], block[4], block[9], block[14]);
        }

        for (int i = 0; i < 16; ++i) {
            block[i] += state[i];
            keystream[i * 4 + 0] = block[i] & 0xFF;
            keystream[i * 4 + 1] = (block[i] >> 8) & 0xFF;
            keystream[i * 4 + 2] = (block[i] >> 16) & 0xFF;
            keystream[i * 4 + 3] = (block[i] >> 24) & 0xFF;
        }

        // Mã hóa/giải mã dữ liệu
        size_t bytesToProcess = min<size_t>(64, input.size() - offset);
        for (size_t i = 0; i < bytesToProcess; ++i) {
            output[offset + i] = input[offset + i] ^ keystream[i];
        }

        ++state[12]; // Tăng counter
        offset += bytesToProcess;
    }
}

int main() {
    // 256-bit key và 96-bit nonce
    uint8_t key[32];
    uint8_t nonce[12];
    for (int i = 0; i < 32; ++i) key[i] = i;
    for (int i = 0; i < 12; ++i) nonce[i] = i;

    // Khởi tạo trạng thái ChaCha20
    uint32_t initialState[16];
    initializeState(initialState, key, nonce, 0);

    // Dữ liệu plaintext
    string plaintext;
    cout << "Enter plaintext: ";
    getline(cin, plaintext);
    vector<uint8_t> plaintextBytes(plaintext.begin(), plaintext.end());
    vector<uint8_t> ciphertext;
    vector<uint8_t> decrypted;

    // Mã hóa
    chachaProcess(initialState, plaintextBytes, ciphertext);

    // In ciphertext (hex)
    cout << "Ciphertext (hex): ";
    for (uint8_t byte : ciphertext) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(byte) << " ";
    }
    cout << endl;

    // Giải mã
    initializeState(initialState, key, nonce, 0); // Reset trạng thái
    chachaProcess(initialState, ciphertext, decrypted);

    // In plaintext giải mã
    cout << "Decrypted text: ";
    for (uint8_t byte : decrypted) {
        cout << static_cast<char>(byte);
    }
    cout << endl;

    return 0;
}
