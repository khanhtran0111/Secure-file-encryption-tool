#include<bits/stdc++.h>
using namespace std;

const uint32_t CONSTANTS[4] = {0x61707865, 0x3320646E, 0x79622D32, 0x6B206574};

inline uint32_t rotate(uint32_t v, uint32_t c) {
    return (v << c) | (v >> (32 - c));
}

inline void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotate(d, 16);
    c += d; b ^= c; b = rotate(b, 12);
    a += b; d ^= a; d = rotate(d, 8);
    c += d; b ^= c; b = rotate(b, 7);
}

void initializeState(uint32_t state[16], const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    memcpy(state, CONSTANTS, sizeof(CONSTANTS));
    for (int i = 0; i < 8; ++i) {
        state[4 + i] = (uint32_t(key[i * 4]) | (uint32_t(key[i * 4 + 1]) << 8) |
                        (uint32_t(key[i * 4 + 2]) << 16) | (uint32_t(key[i * 4 + 3]) << 24));
    }
    state[12] = counter;
    for (int i = 0; i < 3; ++i) {
        state[13 + i] = (uint32_t(nonce[i * 4]) | (uint32_t(nonce[i * 4 + 1]) << 8) |
                         (uint32_t(nonce[i * 4 + 2]) << 16) | (uint32_t(nonce[i * 4 + 3]) << 24));
    }
}

void chachaProcess(const uint32_t initialState[16], const vector<uint8_t>& input, vector<uint8_t>& output) {
    output.resize(input.size());
    uint32_t state[16];
    uint32_t block[16];
    vector<uint8_t> keystream(64);
    size_t offset = 0;

    memcpy(state, initialState, sizeof(state)); 

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
        size_t bytesToProcess = min<size_t>(64, input.size() - offset);
        for (size_t i = 0; i < bytesToProcess; ++i) {
            output[offset + i] = input[offset + i] ^ keystream[i];
        }

        ++state[12];
        offset += bytesToProcess;
    }
}

void processFile(const string& inputFilePath, const string& outputFilePath, const uint8_t key[32], const uint8_t nonce[12], bool encrypt, bool outputHex = false) {
    ifstream inputFile(inputFilePath, ios::binary);
    if (!inputFile) {
        cerr << "Error: Cannot open input file!" << endl;
        return;
    }
    vector<uint8_t> input((istreambuf_iterator<char>(inputFile)), istreambuf_iterator<char>());
    inputFile.close();
    vector<uint8_t> output;
    uint32_t initialState[16];
    initializeState(initialState, key, nonce, 0);
    chachaProcess(initialState, input, output);
    if (outputHex) {
        ofstream outputFile(outputFilePath);
        if (!outputFile) {
            cerr << "Error: Cannot open output file!" << endl;
            return;
        }
        for (uint8_t byte : output) {
            outputFile << hex << setw(2) << setfill('0') << static_cast<int>(byte) << " ";
        }
        outputFile.close();
        cout << (encrypt ? "Encryption" : "Decryption") << " completed in hex. Output saved to " << outputFilePath << endl;
    } else {
        ofstream outputFile(outputFilePath, ios::binary);
        if (!outputFile) {
            cerr << "Error: Cannot open output file!" << endl;
            return;
        }
        outputFile.write(reinterpret_cast<char*>(output.data()), output.size());
        outputFile.close();
        cout << (encrypt ? "Encryption" : "Decryption") << " completed. Output saved to " << outputFilePath << endl;
    }
}


int main(int argc, char* argv[]) {
    if (argc < 4 || argc > 5) {
        cerr << "Usage: chacha20_file_processor <encrypt|decrypt> <input_file> <output_file> [hex]" << endl;
        return 1;
    }

    string operation = argv[1];
    string inputFilePath = argv[2];
    string outputFilePath = argv[3];
    bool outputHex = (argc == 5 && string(argv[4]) == "hex");

    uint8_t key[32];
    uint8_t nonce[12];
    for (int i = 0; i < 32; ++i) key[i] = i;
    for (int i = 0; i < 12; ++i) nonce[i] = i;

    if (operation == "encrypt") {
        processFile(inputFilePath, outputFilePath, key, nonce, true, outputHex);
    } else if (operation == "decrypt") {
        processFile(inputFilePath, outputFilePath, key, nonce, false, outputHex);
    } else {
        cerr << "Invalid operation: Use 'encrypt' or 'decrypt'" << endl;
        return 1;
    }

    return 0;
}
