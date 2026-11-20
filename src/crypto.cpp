// language: C++, file: crypto.cpp, target: Windows 11, MSVC
// *AES-256-GCM + PBKDF2-HMAC-SHA256 via Windows CNG. On-disk: CBOX v1 | salt 16 | nonce 12 | ciphertext | tag 16.*
#include "crypto.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <cstring>
#include <string>

#pragma comment(lib, "bcrypt.lib")

namespace {

constexpr uint8_t kMagic[4] = {'C', 'B', 'O', 'X'};
constexpr uint8_t kVersion = 1;
constexpr ULONG kSaltLen = 16;
constexpr ULONG kNonceLen = 12;
constexpr ULONG kTagLen = 16;
constexpr ULONG kKeyLen = 32;
constexpr ULONG kAadLen = 5;  // magic + version
constexpr size_t kHeaderLen = 4 + 1 + kSaltLen + kNonceLen; // 33: no length field — clen is blob minus header minus tag
constexpr ULONGLONG kPbkdf2Rounds = 210000;
constexpr size_t kMaxPlain = kCboxMaxPlainBytes;

struct UniqueHandle {
    HANDLE h = INVALID_HANDLE_VALUE;

    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE hh) : h(hh) {}
    ~UniqueHandle() { reset(); }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    UniqueHandle(UniqueHandle&& o) noexcept : h(o.h) { o.h = INVALID_HANDLE_VALUE; }
    UniqueHandle& operator=(UniqueHandle&& o) noexcept {
        if (this != &o) {
            reset();
            h = o.h;
            o.h = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    void reset() {
        if (h != INVALID_HANDLE_VALUE && h != nullptr) {
            CloseHandle(h);
            h = INVALID_HANDLE_VALUE;
        }
    }

    HANDLE get() const { return h; }
    bool ok() const { return h != INVALID_HANDLE_VALUE && h != nullptr; }
};

struct Alg {
    BCRYPT_ALG_HANDLE h = nullptr;
    ~Alg() {
        if (h) BCryptCloseAlgorithmProvider(h, 0);
    }
};

struct Key {
    BCRYPT_KEY_HANDLE h = nullptr;
    ~Key() {
        if (h) BCryptDestroyKey(h);
    }
};

bool fail(CryptoError* err, const wchar_t* msg) {
    if (err) err->msg = msg;
    return false;
}

bool nt_fail(NTSTATUS st, CryptoError* err, const wchar_t* what) {
    if (BCRYPT_SUCCESS(st)) return false;
    if (err)
        err->msg = std::wstring(what) + L" (NTSTATUS " + std::to_wstring(static_cast<unsigned long>(st)) + L")";
    return true;
}

bool utf16_to_utf8(const std::wstring& w, std::vector<uint8_t>& out) {
    if (w.empty()) {
        out.clear();
        return true;
    }
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return false;
    out.resize(static_cast<size_t>(n));
    int n2 = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                 reinterpret_cast<char*>(out.data()), n, nullptr, nullptr);
    if (n2 != n) {
        cbox_wipe_bytes(out.data(), out.size());
        out.clear();
        return false;
    }
    return true;
}

bool random_bytes(uint8_t* p, ULONG n, CryptoError* err) {
    NTSTATUS st = BCryptGenRandom(nullptr, p, n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (nt_fail(st, err, L"BCryptGenRandom")) return false;
    return true;
}

bool derive_key(const std::wstring& password, const uint8_t* salt, ULONG salt_len, uint8_t key[kKeyLen],
                CryptoError* err) {
    std::vector<uint8_t> pw;
    if (!utf16_to_utf8(password, pw) || pw.empty()) return fail(err, L"empty password");

    Alg hmac;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hmac.h, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (nt_fail(st, err, L"BCryptOpenAlgorithmProvider HMAC-SHA256")) {
        cbox_wipe_bytes(pw.data(), pw.size());
        return false;
    }

    st = BCryptDeriveKeyPBKDF2(hmac.h, pw.data(), static_cast<ULONG>(pw.size()), const_cast<PUCHAR>(salt), salt_len,
                               kPbkdf2Rounds, key, kKeyLen, 0);
    cbox_wipe_bytes(pw.data(), pw.size());
    if (nt_fail(st, err, L"BCryptDeriveKeyPBKDF2")) {
        cbox_wipe_bytes(key, kKeyLen);
        return false;
    }
    return true;
}

bool open_aes_gcm(Alg& aes, CryptoError* err) {
    NTSTATUS st = BCryptOpenAlgorithmProvider(&aes.h, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (nt_fail(st, err, L"BCryptOpenAlgorithmProvider AES")) return false;
    st = BCryptSetProperty(aes.h, BCRYPT_CHAINING_MODE,
                           reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                           sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (nt_fail(st, err, L"BCryptSetProperty GCM")) return false;
    return true;
}

void fill_gcm_info(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO& info, uint8_t* nonce, uint8_t* tag, uint8_t* aad,
                   ULONG aad_len) {
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = nonce;
    info.cbNonce = kNonceLen;
    info.pbTag = tag;
    info.cbTag = kTagLen;
    info.pbAuthData = aad_len ? aad : nullptr;
    info.cbAuthData = aad_len;
}

bool write_all(HANDLE h, const void* p, size_t n, CryptoError* err) {
    const auto* b = static_cast<const uint8_t*>(p);
    size_t off = 0;
    while (off < n) {
        const DWORD chunk = static_cast<DWORD>((n - off) > 0x100000 ? 0x100000 : (n - off));
        DWORD written = 0;
        if (!WriteFile(h, b + off, chunk, &written, nullptr) || written != chunk)
            return fail(err, L"write failed");
        off += written;
    }
    return true;
}

bool read_exact(HANDLE h, void* p, size_t n, CryptoError* err) {
    auto* b = static_cast<uint8_t*>(p);
    size_t off = 0;
    while (off < n) {
        const DWORD chunk = static_cast<DWORD>((n - off) > 0x100000 ? 0x100000 : (n - off));
        DWORD got = 0;
        if (!ReadFile(h, b + off, chunk, &got, nullptr) || got != chunk)
            return fail(err, L"read failed");
        off += got;
    }
    return true;
}

bool atomic_write(const std::wstring& dst, const uint8_t* p, size_t n, CryptoError* err) {
    const std::wstring tmp = dst + L".tmp";
    UniqueHandle h(CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!h.ok()) return fail(err, L"cannot write output file");

    size_t off = 0;
    while (off < n) {
        const DWORD chunk = static_cast<DWORD>((n - off) > 0x100000 ? 0x100000 : (n - off));
        DWORD written = 0;
        if (!WriteFile(h.get(), p + off, chunk, &written, nullptr) || written != chunk) {
            h.reset();
            DeleteFileW(tmp.c_str());
            return fail(err, L"write failed");
        }
        off += written;
    }
    FlushFileBuffers(h.get());
    h.reset();
    if (!MoveFileExW(tmp.c_str(), dst.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(tmp.c_str());
        return fail(err, L"cannot replace output file");
    }
    return true;
}

}  // namespace

void cbox_wipe_bytes(void* p, size_t n) {
    if (p && n) SecureZeroMemory(p, n);
}

void cbox_wipe_wstring(std::wstring& s) {
    if (!s.empty()) SecureZeroMemory(s.data(), s.size() * sizeof(wchar_t));
    s.clear();
}

bool cbox_encrypt_buffer(const uint8_t* plain, size_t plain_len, const std::wstring& password,
                         std::vector<uint8_t>& out, CryptoError* err, CboxAad aad) {
    out.clear();
    if (plain_len > kMaxPlain) return fail(err, L"file larger than 4 GiB");
    if (plain_len && !plain) return fail(err, L"null plaintext");

    uint8_t salt[kSaltLen];
    uint8_t nonce[kNonceLen];
    if (!random_bytes(salt, kSaltLen, err) || !random_bytes(nonce, kNonceLen, err)) return false;

    uint8_t key[kKeyLen]{};
    if (!derive_key(password, salt, kSaltLen, key, err)) return false;

    Alg aes;
    if (!open_aes_gcm(aes, err)) {
        cbox_wipe_bytes(key, sizeof(key));
        return false;
    }

    Key hk;
    NTSTATUS st = BCryptGenerateSymmetricKey(aes.h, &hk.h, nullptr, 0, key, kKeyLen, 0);
    cbox_wipe_bytes(key, sizeof(key));
    if (nt_fail(st, err, L"BCryptGenerateSymmetricKey")) return false;

    uint8_t aad_buf[kAadLen];
    memcpy(aad_buf, kMagic, 4);
    aad_buf[4] = kVersion;

    uint8_t tag[kTagLen]{};
    uint8_t nonce_copy[kNonceLen];
    memcpy(nonce_copy, nonce, kNonceLen);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    const ULONG aad_len = (aad == CboxAad::On) ? kAadLen : 0;
    fill_gcm_info(info, nonce_copy, tag, aad_buf, aad_len);

    std::vector<uint8_t> cipher(plain_len);
    ULONG cb = 0;
    st = BCryptEncrypt(hk.h, plain_len ? const_cast<PUCHAR>(plain) : nullptr, static_cast<ULONG>(plain_len), &info,
                       nullptr, 0, cipher.empty() ? nullptr : cipher.data(), static_cast<ULONG>(cipher.size()), &cb, 0);
    if (nt_fail(st, err, L"BCryptEncrypt")) {
        cbox_wipe_bytes(cipher.data(), cipher.size());
        return false;
    }
    cipher.resize(cb);

    out.reserve(kHeaderLen + cipher.size() + kTagLen);
    out.insert(out.end(), kMagic, kMagic + 4);
    out.push_back(kVersion);
    out.insert(out.end(), salt, salt + kSaltLen);
    out.insert(out.end(), nonce, nonce + kNonceLen);
    out.insert(out.end(), cipher.begin(), cipher.end());
    out.insert(out.end(), tag, tag + kTagLen);
    cbox_wipe_bytes(cipher.data(), cipher.size());
    return true;
}

bool cbox_decrypt_buffer(const uint8_t* blob, size_t blob_len, const std::wstring& password,
                         std::vector<uint8_t>& plain, CryptoError* err) {
    plain.clear();
    if (!blob) return fail(err, L"truncated .cbox");
    if (blob_len < kHeaderLen + kTagLen) return fail(err, L"truncated .cbox");
    if (blob_len > kHeaderLen + kMaxPlain + kTagLen) return fail(err, L"file larger than 4 GiB");
    if (memcmp(blob, kMagic, 4) != 0) return fail(err, L"not a CBOX file");
    if (blob[4] != kVersion) return fail(err, L"unsupported version");

    const uint8_t* salt = blob + 5;
    const uint8_t* nonce = salt + kSaltLen;
    const size_t clen = blob_len - kHeaderLen - kTagLen;
    if (clen > kMaxPlain) return fail(err, L"file larger than 4 GiB");
    const uint8_t* cipher = nonce + kNonceLen;
    const uint8_t* tag = cipher + clen;

    uint8_t key[kKeyLen]{};
    if (!derive_key(password, salt, kSaltLen, key, err)) return false;

    Alg aes;
    if (!open_aes_gcm(aes, err)) {
        cbox_wipe_bytes(key, sizeof(key));
        return false;
    }
    Key hk;
    NTSTATUS st = BCryptGenerateSymmetricKey(aes.h, &hk.h, nullptr, 0, key, kKeyLen, 0);
    cbox_wipe_bytes(key, sizeof(key));
    if (nt_fail(st, err, L"BCryptGenerateSymmetricKey")) return false;

    uint8_t aad_buf[kAadLen];
    memcpy(aad_buf, blob, kAadLen);
    uint8_t tag_copy[kTagLen];
    uint8_t nonce_copy[kNonceLen];

    auto try_decrypt = [&](ULONG aad_len) -> NTSTATUS {
        memcpy(tag_copy, tag, kTagLen);
        memcpy(nonce_copy, nonce, kNonceLen);
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        fill_gcm_info(info, nonce_copy, tag_copy, aad_buf, aad_len);
        ULONG cb = 0;
        plain.assign(clen, 0);
        NTSTATUS s = BCryptDecrypt(hk.h, clen ? const_cast<PUCHAR>(cipher) : nullptr, static_cast<ULONG>(clen), &info, nullptr, 0,
                                   plain.empty() ? nullptr : plain.data(), static_cast<ULONG>(plain.size()), &cb, 0);
        if (BCRYPT_SUCCESS(s)) plain.resize(cb);
        else {
            cbox_wipe_bytes(plain.data(), plain.size());
            plain.clear();
        }
        return s;
    };

    st = try_decrypt(kAadLen);
    if (!BCRYPT_SUCCESS(st)) st = try_decrypt(0);
    if (nt_fail(st, err, L"auth failed (wrong password or corrupt file)")) return false;
    return true;
}

struct FileMap {
    UniqueHandle file;
    UniqueHandle section;
    uint8_t* view = nullptr;
    size_t size = 0;
    ~FileMap() {
        if (view) UnmapViewOfFile(view);
    }
};

bool map_ro(const std::wstring& path, FileMap& m, CryptoError* err) {
    m.file = UniqueHandle(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!m.file.ok()) return fail(err, L"cannot open input file");
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(m.file.get(), &sz) || sz.QuadPart < 0) return fail(err, L"cannot size input file");
    m.size = static_cast<size_t>(sz.QuadPart);
    if (m.size == 0) return true;
    HANDLE sec = CreateFileMappingW(m.file.get(), nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!sec) return fail(err, L"cannot map input file");
    m.section = UniqueHandle(sec);
    m.view = static_cast<uint8_t*>(MapViewOfFile(sec, FILE_MAP_READ, 0, 0, 0));
    if (!m.view) return fail(err, L"cannot map input file");
    return true;
}

bool map_rw_create(const std::wstring& path, size_t size, FileMap& m, CryptoError* err) {
    m.file = UniqueHandle(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                      FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!m.file.ok()) return fail(err, L"cannot write output file");
    LARGE_INTEGER li{};
    li.QuadPart = static_cast<LONGLONG>(size);
    if (!SetFilePointerEx(m.file.get(), li, nullptr, FILE_BEGIN) || !SetEndOfFile(m.file.get()))
        return fail(err, L"cannot size output file");
    m.size = size;
    if (size == 0) return true;
    HANDLE sec = CreateFileMappingW(m.file.get(), nullptr, PAGE_READWRITE, 0, 0, nullptr);
    if (!sec) return fail(err, L"cannot map output file");
    m.section = UniqueHandle(sec);
    m.view = static_cast<uint8_t*>(MapViewOfFile(sec, FILE_MAP_WRITE, 0, 0, 0));
    if (!m.view) return fail(err, L"cannot map output file");
    return true;
}

bool cbox_encrypt_file(const std::wstring& src, const std::wstring& dst, const std::wstring& password,
                       CryptoError* err) {
    FileMap in;
    if (!map_ro(src, in, err)) return false;
    if (in.size > kMaxPlain) return fail(err, L"file larger than 4 GiB");

    uint8_t salt[kSaltLen];
    uint8_t nonce[kNonceLen];
    uint8_t tag[kTagLen]{};
    if (!random_bytes(salt, kSaltLen, err) || !random_bytes(nonce, kNonceLen, err)) return false;

    uint8_t key[kKeyLen]{};
    if (!derive_key(password, salt, kSaltLen, key, err)) return false;
    Alg aes;
    if (!open_aes_gcm(aes, err)) {
        cbox_wipe_bytes(key, sizeof(key));
        return false;
    }
    Key hk;
    NTSTATUS st = BCryptGenerateSymmetricKey(aes.h, &hk.h, nullptr, 0, key, kKeyLen, 0);
    cbox_wipe_bytes(key, sizeof(key));
    if (nt_fail(st, err, L"BCryptGenerateSymmetricKey")) return false;

    uint8_t aad_buf[kAadLen];
    memcpy(aad_buf, kMagic, 4);
    aad_buf[4] = kVersion;
    uint8_t nonce_work[kNonceLen];
    memcpy(nonce_work, nonce, kNonceLen);

    const std::wstring tmp = dst + L".tmp";
    FileMap out;
    if (!map_rw_create(tmp, kHeaderLen + in.size + kTagLen, out, err)) {
        DeleteFileW(tmp.c_str());
        return false;
    }
    memcpy(out.view, kMagic, 4);
    out.view[4] = kVersion;
    memcpy(out.view + 5, salt, kSaltLen);
    memcpy(out.view + 5 + kSaltLen, nonce, kNonceLen);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    fill_gcm_info(info, nonce_work, tag, aad_buf, kAadLen);
    ULONG cb = 0;
    st = BCryptEncrypt(hk.h, in.size ? in.view : nullptr, static_cast<ULONG>(in.size), &info, nullptr, 0,
                       in.size ? out.view + kHeaderLen : nullptr, static_cast<ULONG>(in.size), &cb, 0);
    if (nt_fail(st, err, L"BCryptEncrypt")) {
        if (out.view) UnmapViewOfFile(out.view);
        out.view = nullptr;
        out.section.reset();
        out.file.reset();
        DeleteFileW(tmp.c_str());
        return false;
    }
    memcpy(out.view + kHeaderLen + in.size, tag, kTagLen);
    FlushViewOfFile(out.view, 0);
    FlushFileBuffers(out.file.get());
    UnmapViewOfFile(out.view);
    out.view = nullptr;
    out.section.reset();
    out.file.reset();
    if (!MoveFileExW(tmp.c_str(), dst.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(tmp.c_str());
        return fail(err, L"cannot replace output file");
    }
    return true;
}

bool cbox_decrypt_file(const std::wstring& src, const std::wstring& dst, const std::wstring& password,
                       CryptoError* err) {
    FileMap in;
    if (!map_ro(src, in, err)) return false;
    if (in.size < kHeaderLen + kTagLen) return fail(err, L"truncated .cbox");
    const size_t clen = in.size - kHeaderLen - kTagLen;
    if (clen > kMaxPlain) return fail(err, L"file larger than 4 GiB");
    if (memcmp(in.view, kMagic, 4) != 0) return fail(err, L"not a CBOX file");
    if (in.view[4] != kVersion) return fail(err, L"unsupported version");

    const uint8_t* salt = in.view + 5;
    const uint8_t* nonce = salt + kSaltLen;
    const uint8_t* cipher = nonce + kNonceLen;
    const uint8_t* tag = in.view + in.size - kTagLen;

    uint8_t key[kKeyLen]{};
    if (!derive_key(password, salt, kSaltLen, key, err)) return false;
    Alg aes;
    if (!open_aes_gcm(aes, err)) {
        cbox_wipe_bytes(key, sizeof(key));
        return false;
    }
    Key hk;
    NTSTATUS st = BCryptGenerateSymmetricKey(aes.h, &hk.h, nullptr, 0, key, kKeyLen, 0);
    cbox_wipe_bytes(key, sizeof(key));
    if (nt_fail(st, err, L"BCryptGenerateSymmetricKey")) return false;

    const std::wstring tmp = dst + L".tmp";
    FileMap out;
    if (!map_rw_create(tmp, clen, out, err)) {
        DeleteFileW(tmp.c_str());
        return false;
    }

    auto try_dec = [&](ULONG aad_len) -> NTSTATUS {
        uint8_t tag_copy[kTagLen];
        uint8_t nonce_copy[kNonceLen];
        memcpy(tag_copy, tag, kTagLen);
        memcpy(nonce_copy, nonce, kNonceLen);
        uint8_t aad_buf[kAadLen];
        memcpy(aad_buf, in.view, kAadLen);
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        fill_gcm_info(info, nonce_copy, tag_copy, aad_buf, aad_len);
        ULONG cb = 0;
        return BCryptDecrypt(hk.h, clen ? const_cast<PUCHAR>(cipher) : nullptr, static_cast<ULONG>(clen), &info,
                             nullptr, 0, clen ? out.view : nullptr, static_cast<ULONG>(clen), &cb, 0);
    };

    st = try_dec(kAadLen);
    if (!BCRYPT_SUCCESS(st)) st = try_dec(0);
    if (nt_fail(st, err, L"auth failed (wrong password or corrupt file)")) {
        if (out.view) {
            cbox_wipe_bytes(out.view, clen);
            UnmapViewOfFile(out.view);
            out.view = nullptr;
        }
        out.section.reset();
        out.file.reset();
        DeleteFileW(tmp.c_str());
        return false;
    }
    if (out.view) {
        FlushViewOfFile(out.view, 0);
        UnmapViewOfFile(out.view);
        out.view = nullptr;
    }
    FlushFileBuffers(out.file.get());
    out.section.reset();
    out.file.reset();
    if (!MoveFileExW(tmp.c_str(), dst.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(tmp.c_str());
        return fail(err, L"cannot replace output file");
    }
    return true;
}
