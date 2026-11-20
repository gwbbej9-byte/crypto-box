// language: C++, file: cbox_tests.cpp, target: Windows 11, MSVC
// *Console tests for CBOX crypto. No Win32 UI.*
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "crypto.hpp"

namespace {

int g_fail = 0;
int g_pass = 0;

void expect(bool cond, const char* name) {
    if (cond) {
        ++g_pass;
        std::printf("PASS  %s\n", name);
    } else {
        ++g_fail;
        std::printf("FAIL  %s\n", name);
    }
}

std::wstring temp_dir() {
    wchar_t tmp[MAX_PATH]{};
    GetTempPathW(MAX_PATH, tmp);
    std::wstring dir = std::wstring(tmp) + L"cbox-unit-" + std::to_wstring(GetCurrentProcessId());
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

bool write_raw(const std::wstring& path, const uint8_t* p, size_t n) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD w = 0;
    const BOOL ok = n ? WriteFile(h, p, static_cast<DWORD>(n), &w, nullptr) : TRUE;
    CloseHandle(h);
    return ok && w == n;
}

bool read_raw(const std::wstring& path, std::vector<uint8_t>& out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0) {
        CloseHandle(h);
        return false;
    }
    out.assign(static_cast<size_t>(sz.QuadPart), 0);
    DWORD got = 0;
    const BOOL ok = out.empty() || ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &got, nullptr);
    CloseHandle(h);
    return ok && got == out.size();
}

}  // namespace

int main() {
    const std::wstring dir = temp_dir();
    const std::wstring src = dir + L"\\plain.bin";
    const std::wstring box = dir + L"\\plain.cbox";
    const std::wstring outp = dir + L"\\out.bin";
    const std::wstring huge = dir + L"\\huge.bin";

    const uint8_t payload[] = {'a', 't', 't', 'a', 'c', 'k', ' ', 'a', 't', ' ', 'd', 'a', 'w', 'n'};
    expect(write_raw(src, payload, sizeof(payload)), "write plaintext fixture");

    std::wstring pw = L"correct-horse-battery";
    CryptoError err;

    expect(cbox_encrypt_file(src, box, pw, &err), "encrypt file");
    expect(cbox_decrypt_file(box, outp, pw, &err), "decrypt file");

    std::vector<uint8_t> round;
    expect(read_raw(outp, round), "read roundtrip output");
    expect(round.size() == sizeof(payload) && memcmp(round.data(), payload, sizeof(payload)) == 0, "roundtrip bytes");

    std::wstring wrong = L"wrong-password";
    DeleteFileW(outp.c_str());
    const bool bad_pw = cbox_decrypt_file(box, outp, wrong, &err);
    expect(!bad_pw, "wrong password fails");
    expect(GetFileAttributesW(outp.c_str()) == INVALID_FILE_ATTRIBUTES, "wrong password writes no file");
    cbox_wipe_wstring(wrong);

    std::vector<uint8_t> blob;
    expect(read_raw(box, blob), "read ciphertext");
    expect(blob.size() >= 16, "ciphertext has tag");

    std::vector<uint8_t> trunc = blob;
    trunc.resize(blob.size() / 2);
    std::vector<uint8_t> plain;
    expect(!cbox_decrypt_buffer(trunc.data(), trunc.size(), pw, plain, &err), "truncated fails");

    std::vector<uint8_t> flipped = blob;
    flipped.back() ^= 0x01;
    expect(!cbox_decrypt_buffer(flipped.data(), flipped.size(), pw, plain, &err), "bit-flip tag fails");

    std::vector<uint8_t> legacy;
    expect(cbox_encrypt_buffer(payload, sizeof(payload), pw, legacy, &err, CboxAad::Off), "legacy encrypt no AAD");
    expect(cbox_decrypt_buffer(legacy.data(), legacy.size(), pw, plain, &err), "decrypt fallback for old files");
    expect(plain.size() == sizeof(payload) && memcmp(plain.data(), payload, sizeof(payload)) == 0,
           "legacy plaintext matches");
    cbox_wipe_bytes(plain.data(), plain.size());

    const size_t big_n = 3u * 1024u * 1024u + 17u;
    std::vector<uint8_t> big(big_n);
    for (size_t i = 0; i < big_n; ++i) big[i] = static_cast<uint8_t>(i * 13u);
    expect(write_raw(huge, big.data(), big.size()), "write 3 MiB stream fixture");
    const std::wstring huge_box = dir + L"\\huge.cbox";
    const std::wstring huge_out = dir + L"\\huge.out";
    expect(cbox_encrypt_file(huge, huge_box, pw, &err), "encrypt 3 MiB streamed");
    expect(cbox_decrypt_file(huge_box, huge_out, pw, &err), "decrypt 3 MiB streamed");
    std::vector<uint8_t> big_round;
    expect(read_raw(huge_out, big_round), "read streamed output");
    expect(big_round == big, "3 MiB roundtrip bytes");
    DeleteFileW(huge_box.c_str());
    DeleteFileW(huge_out.c_str());

    cbox_wipe_wstring(pw);
    DeleteFileW(src.c_str());
    DeleteFileW(box.c_str());
    DeleteFileW(outp.c_str());
    DeleteFileW(huge.c_str());
    RemoveDirectoryW(dir.c_str());

    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
