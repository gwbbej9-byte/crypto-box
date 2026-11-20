#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct CryptoError {
    std::wstring msg;
};

enum class CboxAad {
    On,
    Off,  // only for decrypting boxes written before AAD; production encrypt stays On
};

constexpr size_t kCboxMaxPlainBytes = 0xFFFFFFFFull; // CNG ULONG; files stream in 1 MiB GCM chunks

void cbox_wipe_bytes(void* p, size_t n);
void cbox_wipe_wstring(std::wstring& s);

bool cbox_encrypt_buffer(const uint8_t* plain, size_t plain_len, const std::wstring& password,
                         std::vector<uint8_t>& out, CryptoError* err, CboxAad aad = CboxAad::On);

bool cbox_decrypt_buffer(const uint8_t* blob, size_t blob_len, const std::wstring& password,
                         std::vector<uint8_t>& plain, CryptoError* err);

bool cbox_encrypt_file(const std::wstring& src, const std::wstring& dst, const std::wstring& password,
                       CryptoError* err);

bool cbox_decrypt_file(const std::wstring& src, const std::wstring& dst, const std::wstring& password,
                       CryptoError* err);
