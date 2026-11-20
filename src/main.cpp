// language: C++, file: main.cpp, target: Windows 11, MSVC
// *Win32 dark UI for AES-256-GCM file box. Links: user32 gdi32 comdlg32 bcrypt.*
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>
#include <commdlg.h>
#include <string>
#include "crypto.hpp"

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comdlg32.lib")

static const COLORREF kBg = RGB(18, 20, 26);
static const COLORREF kPanel = RGB(27, 30, 39);
static const COLORREF kText = RGB(230, 232, 238);
static const COLORREF kMuted = RGB(139, 144, 160);
static const COLORREF kAccent = RGB(61, 139, 253);
static const COLORREF kOk = RGB(61, 220, 151);
static const COLORREF kErr = RGB(240, 113, 120);

struct App {
    HWND wnd = nullptr;
    HWND edit = nullptr;
    HWND log = nullptr;
    HBRUSH bg = nullptr;
    HBRUSH panel = nullptr;
    HBRUSH edit_bg = nullptr;
    HFONT title = nullptr;
    HFONT body = nullptr;
    HFONT mono = nullptr;
    RECT btn_enc{40, 168, 250, 214};
    RECT btn_dec{270, 168, 480, 214};
    int hover = 0;
    bool demo = false;
    int demo_step = 0;
    std::wstring demo_pw = L"correct-horse";
    std::wstring demo_plain;
    std::wstring demo_cbox;
    std::wstring demo_out;
};

static App g;

static void append_log(const std::wstring& line) {
    int len = GetWindowTextLengthW(g.log);
    SendMessageW(g.log, EM_SETSEL, len, len);
    std::wstring s = line + L"\r\n";
    SendMessageW(g.log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(s.c_str()));
}

static std::wstring password() {
    wchar_t buf[256]{};
    GetWindowTextW(g.edit, buf, 256);
    std::wstring pw(buf);
    SecureZeroMemory(buf, sizeof(buf));
    return pw;
}

static std::wstring pick_open(const wchar_t* filter, const wchar_t* title) {
    wchar_t file[MAX_PATH]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g.wnd;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    if (!GetOpenFileNameW(&ofn)) return {};
    return file;
}

static std::wstring pick_save(const wchar_t* filter, const wchar_t* title, const wchar_t* def) {
    wchar_t file[MAX_PATH]{};
    if (def) wcsncpy_s(file, def, _TRUNCATE);
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g.wnd;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_EXPLORER | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) return {};
    return file;
}

static std::wstring with_ext(const std::wstring& path, const wchar_t* ext) {
    auto slash = path.find_last_of(L"\\/");
    auto dot = path.find_last_of(L'.');
    if (dot == std::wstring::npos || (slash != std::wstring::npos && dot < slash))
        return path + ext;
    return path.substr(0, dot) + ext;
}

static std::wstring strip_cbox(const std::wstring& path) {
    const std::wstring ext = L".cbox";
    if (path.size() > ext.size() && _wcsicmp(path.c_str() + path.size() - ext.size(), ext.c_str()) == 0)
        return path.substr(0, path.size() - ext.size());
    return path + L".bin";
}

static void do_encrypt() {
    auto pw = password();
    if (pw.empty()) {
        append_log(L"[err] password is empty");
        return;
    }
    auto src = pick_open(L"All files\0*.*\0", L"Encrypt file");
    if (src.empty()) {
        cbox_wipe_wstring(pw);
        return;
    }
    auto dst = pick_save(L"crypto-box (*.cbox)\0*.cbox\0", L"Save ciphertext", with_ext(src, L".cbox").c_str());
    if (dst.empty()) {
        cbox_wipe_wstring(pw);
        return;
    }
    append_log(L"[..] PBKDF2-HMAC-SHA256 210000 rounds, AES-256-GCM");
    CryptoError err;
    if (!cbox_encrypt_file(src, dst, pw, &err)) {
        cbox_wipe_wstring(pw);
        append_log(L"[err] " + err.msg);
        return;
    }
    cbox_wipe_wstring(pw);
    append_log(L"[ok]  " + dst);
}

static bool write_text_file(const std::wstring& path, const std::string& text) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD w = 0;
    WriteFile(h, text.data(), static_cast<DWORD>(text.size()), &w, nullptr);
    CloseHandle(h);
    return true;
}

static void demo_encrypt() {
    append_log(L"[..] PBKDF2-HMAC-SHA256 210000 rounds, AES-256-GCM");
    auto pw = password();
    CryptoError err;
    if (!cbox_encrypt_file(g.demo_plain, g.demo_cbox, pw, &err)) {
        cbox_wipe_wstring(pw);
        append_log(L"[err] " + err.msg);
        return;
    }
    cbox_wipe_wstring(pw);
    append_log(L"[ok]  " + g.demo_cbox);
}

static void demo_decrypt() {
    append_log(L"[..] authenticating tag, deriving key");
    auto pw = password();
    CryptoError err;
    if (!cbox_decrypt_file(g.demo_cbox, g.demo_out, pw, &err)) {
        cbox_wipe_wstring(pw);
        append_log(L"[err] " + err.msg);
        return;
    }
    cbox_wipe_wstring(pw);
    append_log(L"[ok]  " + g.demo_out);
}

static void do_decrypt() {
    auto pw = password();
    if (pw.empty()) {
        append_log(L"[err] password is empty");
        return;
    }
    auto src = pick_open(L"crypto-box (*.cbox)\0*.cbox\0All files\0*.*\0", L"Open .cbox");
    if (src.empty()) {
        cbox_wipe_wstring(pw);
        return;
    }
    auto dst = pick_save(L"All files\0*.*\0", L"Save plaintext", strip_cbox(src).c_str());
    if (dst.empty()) {
        cbox_wipe_wstring(pw);
        return;
    }
    append_log(L"[..] authenticating tag, deriving key");
    CryptoError err;
    if (!cbox_decrypt_file(src, dst, pw, &err)) {
        cbox_wipe_wstring(pw);
        append_log(L"[err] " + err.msg);
        return;
    }
    cbox_wipe_wstring(pw);
    append_log(L"[ok]  " + dst);
}

static int hit_button(int x, int y) {
    POINT p{x, y};
    if (PtInRect(&g.btn_enc, p)) return 1;
    if (PtInRect(&g.btn_dec, p)) return 2;
    return 0;
}

static void paint_button(HDC hdc, const RECT& r, const wchar_t* label, bool hover) {
    HBRUSH br = CreateSolidBrush(hover ? kAccent : kPanel);
    HPEN pen = CreatePen(PS_SOLID, 1, kAccent);
    HGDIOBJ oldb = SelectObject(hdc, br);
    HGDIOBJ oldp = SelectObject(hdc, pen);
    RoundRect(hdc, r.left, r.top, r.right, r.bottom, 10, 10);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, hover ? RGB(255, 255, 255) : kText);
    SelectObject(hdc, g.body);
    DrawTextW(hdc, label, -1, const_cast<RECT*>(&r), DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(hdc, oldb);
    SelectObject(hdc, oldp);
    DeleteObject(br);
    DeleteObject(pen);
}

static void on_paint(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    RECT rc;
    GetClientRect(hwnd, &rc);
    FillRect(hdc, &rc, g.bg);

    SetBkMode(hdc, TRANSPARENT);
    SelectObject(hdc, g.title);
    SetTextColor(hdc, kText);
    RECT t{40, 28, rc.right - 40, 64};
    DrawTextW(hdc, L"crypto-box", -1, &t, DT_LEFT | DT_SINGLELINE);

    SelectObject(hdc, g.body);
    SetTextColor(hdc, kMuted);
    RECT s{40, 64, rc.right - 40, 92};
    DrawTextW(hdc, L"C++20  ·  AES-256-GCM  ·  PBKDF2-HMAC-SHA256  ·  Windows CNG", -1, &s,
              DT_LEFT | DT_SINGLELINE);

    SetTextColor(hdc, kMuted);
    RECT pl{40, 118, 200, 142};
    DrawTextW(hdc, L"password", -1, &pl, DT_LEFT | DT_SINGLELINE);

    paint_button(hdc, g.btn_enc, L"Encrypt file", g.hover == 1);
    paint_button(hdc, g.btn_dec, L"Decrypt file", g.hover == 2);

    EndPaint(hwnd, &ps);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        g.bg = CreateSolidBrush(kBg);
        g.panel = CreateSolidBrush(kPanel);
        g.edit_bg = CreateSolidBrush(RGB(22, 24, 32));
        g.title = CreateFontW(32, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                              OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                              DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        g.body = CreateFontW(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        g.mono = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             FIXED_PITCH | FF_MODERN, L"Consolas");
        g.edit = CreateWindowExW(0, L"EDIT", L"",
                                 WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL,
                                 40, 142, 440, 18 + 8, hwnd, reinterpret_cast<HMENU>(1), nullptr, nullptr);
        SendMessageW(g.edit, WM_SETFONT, reinterpret_cast<WPARAM>(g.body), TRUE);
        g.log = CreateWindowExW(0, L"EDIT", L"",
                                WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                                40, 236, 640, 200, hwnd, reinterpret_cast<HMENU>(2), nullptr, nullptr);
        SendMessageW(g.log, WM_SETFONT, reinterpret_cast<WPARAM>(g.mono), TRUE);
        append_log(L"ready. format: CBOX v1 | salt 16 | nonce 12 | ciphertext | tag 16");
        append_log(L"key never written to disk. tag fail = wrong password or bit flip.");
        if (g.demo) SetTimer(hwnd, 1, 180, nullptr);
        return 0;
    }
    case WM_TIMER: {
        if (!g.demo) return 0;
        const auto& pw = g.demo_pw;
        if (g.demo_step < static_cast<int>(pw.size())) {
            std::wstring sofar = pw.substr(0, static_cast<size_t>(g.demo_step) + 1);
            SetWindowTextW(g.edit, sofar.c_str());
            g.demo_step++;
            return 0;
        }
        if (g.demo_step == static_cast<int>(pw.size())) {
            g.hover = 1;
            InvalidateRect(hwnd, &g.btn_enc, FALSE);
            g.demo_step++;
            return 0;
        }
        if (g.demo_step == static_cast<int>(pw.size()) + 1) {
            demo_encrypt();
            g.hover = 0;
            InvalidateRect(hwnd, &g.btn_enc, FALSE);
            g.demo_step++;
            return 0;
        }
        if (g.demo_step < static_cast<int>(pw.size()) + 6) {
            g.demo_step++;
            return 0;
        }
        if (g.demo_step == static_cast<int>(pw.size()) + 6) {
            g.hover = 2;
            InvalidateRect(hwnd, &g.btn_dec, FALSE);
            g.demo_step++;
            return 0;
        }
        if (g.demo_step == static_cast<int>(pw.size()) + 7) {
            demo_decrypt();
            g.hover = 0;
            InvalidateRect(hwnd, &g.btn_dec, FALSE);
            g.demo_step++;
            return 0;
        }
        KillTimer(hwnd, 1);
        return 0;
    }
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC: {
        HDC hdc = reinterpret_cast<HDC>(wParam);
        SetTextColor(hdc, kText);
        SetBkColor(hdc, RGB(22, 24, 32));
        return reinterpret_cast<LRESULT>(g.edit_bg);
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        on_paint(hwnd);
        return 0;
    case WM_MOUSEMOVE: {
        int h = hit_button(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
        if (h != g.hover) {
            g.hover = h;
            InvalidateRect(hwnd, &g.btn_enc, FALSE);
            InvalidateRect(hwnd, &g.btn_dec, FALSE);
        }
        return 0;
    }
    case WM_LBUTTONDOWN: {
        int h = hit_button(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
        if (h == 1) do_encrypt();
        if (h == 2) do_decrypt();
        return 0;
    }
    case WM_DESTROY:
        DeleteObject(g.bg);
        DeleteObject(g.panel);
        DeleteObject(g.edit_bg);
        DeleteObject(g.title);
        DeleteObject(g.body);
        DeleteObject(g.mono);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hi, HINSTANCE, PWSTR cmd, int show) {
    if (cmd && wcsstr(cmd, L"--demo")) {
        g.demo = true;
        wchar_t tmp[MAX_PATH]{};
        GetTempPathW(MAX_PATH, tmp);
        std::wstring dir = std::wstring(tmp) + L"cbox-demo";
        CreateDirectoryW(dir.c_str(), nullptr);
        g.demo_plain = dir + L"\\note.txt";
        g.demo_cbox = dir + L"\\note.cbox";
        g.demo_out = dir + L"\\note.out.txt";
        write_text_file(g.demo_plain, "attack at dawn\r\n");
    }
    SetProcessDPIAware();
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hi;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(kBg);
    wc.lpszClassName = L"CryptoBoxWnd";
    wc.hIcon = LoadIcon(nullptr, IDI_SHIELD);
    RegisterClassExW(&wc);

    RECT r{0, 0, 720, 480};
    AdjustWindowRect(&r, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE);
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"crypto-box",
                                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                                80, 80, r.right - r.left, r.bottom - r.top,
                                nullptr, nullptr, hi, nullptr);
    g.wnd = hwnd;
    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
