// main.cpp — Process Dumper GUI (Extreme Injector Dark Theme)
// *the window materializes like a ghost in the taskbar, hunting for PIDs*
#include <windows.h>
#include <commctrl.h>
#include <windowsx.h>
#include <uxtheme.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include "dumper.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "gdiplus.lib")

// ─────────────────────────────────────────────────────────────────────────────
// Control IDs
// ─────────────────────────────────────────────────────────────────────────────
#define IDC_LIST_PROC     1001
#define IDC_BTN_REFRESH   1002
#define IDC_BTN_DUMP      1003
#define IDC_BTN_CLEAR     1004
#define IDC_BTN_OPENFOLDER 1005
#define IDC_EDIT_LOG      1006
#define IDC_EDIT_FILTER   1007
#define IDC_STATUS        1008
#define IDC_LABEL_PROC    1009
#define IDC_LABEL_LOG     1010
#define IDC_HEADER        1011
#define IDC_PROGRESS      1012

#define WM_DUMP_PROGRESS  (WM_APP + 1)
#define WM_DUMP_DONE      (WM_APP + 2)

// ─────────────────────────────────────────────────────────────────────────────
// Color palette — deep space dark like Extreme Injector
// ─────────────────────────────────────────────────────────────────────────────
#define C_BG         RGB(13,  13,  23)
#define C_PANEL      RGB(20,  20,  38)
#define C_PANEL2     RGB(28,  28,  50)
#define C_BORDER     RGB(45,  45,  80)
#define C_ACCENT     RGB(0,   170, 255)
#define C_ACCENT2    RGB(120, 0,   255)
#define C_ACCENT3    RGB(0,   255, 160)
#define C_TEXT       RGB(210, 210, 235)
#define C_TEXT_DIM   RGB(100, 100, 135)
#define C_TEXT_BRIGHT RGB(255,255,255)
#define C_BTN        RGB(30,  30,  55)
#define C_BTN_HOV    RGB(0,   110, 180)
#define C_BTN_ACT    RGB(0,   80,  140)
#define C_SEL_BG     RGB(0,   70,  130)
#define C_SEL_TXT    RGB(255, 255, 255)
#define C_ERR        RGB(255, 80,  80)
#define C_OK         RGB(80,  255, 140)

// ─────────────────────────────────────────────────────────────────────────────
// Globals
// ─────────────────────────────────────────────────────────────────────────────
static HWND  g_hWnd       = nullptr;
static HWND  g_hList      = nullptr;
static HWND  g_hLog       = nullptr;
static HWND  g_hFilter    = nullptr;
static HWND  g_hProgress  = nullptr;
static HWND  g_hStatus    = nullptr;
static HWND  g_hBtnRefresh= nullptr;
static HWND  g_hBtnDump   = nullptr;
static HWND  g_hBtnClear  = nullptr;
static HWND  g_hBtnOpen   = nullptr;

static HBRUSH g_brBg     = nullptr;
static HBRUSH g_brPanel  = nullptr;
static HBRUSH g_brPanel2 = nullptr;
static HBRUSH g_brBtn    = nullptr;
static HFONT  g_fontTitle = nullptr;
static HFONT  g_fontMain  = nullptr;
static HFONT  g_fontMono  = nullptr;
static HFONT  g_fontSmall = nullptr;

static std::vector<ProcessEntry> g_procList;
static std::atomic<bool>         g_dumping{false};
static std::wstring              g_lastOutputPath;

// Hover tracking for buttons
static HWND g_hoverBtn = nullptr;

// ─────────────────────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────────────────────

static void LogAppend(const std::wstring& msg) {
    if (!g_hLog) return;
    int len = GetWindowTextLengthW(g_hLog);
    SendMessageW(g_hLog, EM_SETSEL, len, len);
    SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)(msg + L"\r\n").c_str());
    SendMessageW(g_hLog, EM_SCROLLCARET, 0, 0);
}

static void SetStatus(const std::wstring& msg, COLORREF col = C_TEXT_DIM) {
    if (!g_hStatus) return;
    SetWindowTextW(g_hStatus, msg.c_str());
    // Force repaint of status bar area
    RECT r;
    GetClientRect(g_hWnd, &r);
    r.top = r.bottom - 26;
    InvalidateRect(g_hWnd, &r, TRUE);
}

static std::wstring GetGameFolderName(const std::wstring& procName) {
    std::wstring clean = procName;
    size_t dot = clean.rfind(L'.');
    if (dot != std::wstring::npos) {
        clean = clean.substr(0, dot);
    }
    std::wstring valid;
    for (wchar_t c : clean) {
        if (c == L'\\' || c == L'/' || c == L':' || c == L'*' || c == L'?' || c == L'"' || c == L'<' || c == L'>' || c == L'|')
            continue;
        valid += c;
    }
    if (valid.empty()) valid = L"game_dump";
    return valid;
}

static std::wstring GetGameOutputDir(const std::wstring& procName) {
    wchar_t exeDir[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exeDir, MAX_PATH);
    for (int i = (int)wcslen(exeDir) - 1; i >= 0; i--) {
        if (exeDir[i] == L'\\' || exeDir[i] == L'/') {
            exeDir[i] = 0;
            break;
        }
    }
    std::wstring folderName = GetGameFolderName(procName);
    std::wstring gameDir = std::wstring(exeDir) + L"\\" + folderName;
    CreateDirectoryW(gameDir.c_str(), NULL);
    return gameDir;
}

static std::wstring GetOutputPath(const std::wstring& procName = L"") {
    if (procName.empty()) {
        wchar_t exeDir[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exeDir, MAX_PATH);
        for (int i = (int)wcslen(exeDir) - 1; i >= 0; i--) {
            if (exeDir[i] == L'\\' || exeDir[i] == L'/') {
                exeDir[i] = 0;
                break;
            }
        }
        return std::wstring(exeDir) + L"\\offsets.txt";
    }
    return GetGameOutputDir(procName) + L"\\offsets.txt";
}

// ─────────────────────────────────────────────────────────────────────────────
// Process list refresh
// ─────────────────────────────────────────────────────────────────────────────

static void RefreshProcessList() {
    SetStatus(L"Refreshing process list...", C_TEXT_DIM);
    g_procList = EnumerateProcesses();

    // Get filter text
    wchar_t filter[128] = {};
    GetWindowTextW(g_hFilter, filter, 128);
    std::wstring filterLow = filter;
    for (auto& c : filterLow) c = towlower(c);

    SendMessageW(g_hList, LB_RESETCONTENT, 0, 0);
    int added = 0;
    for (size_t i = 0; i < g_procList.size(); i++) {
        std::wstring nameLow = g_procList[i].name;
        for (auto& c : nameLow) c = towlower(c);

        if (!filterLow.empty() && nameLow.find(filterLow) == std::wstring::npos)
            continue;

        wchar_t entry[256];
        swprintf_s(entry, L"[%5lu]  %s%s",
            g_procList[i].pid,
            g_procList[i].name.c_str(),
            g_procList[i].is64bit ? L"  [x64]" : L"  [x86]");
        SendMessageW(g_hList, LB_ADDSTRING, 0, (LPARAM)entry);
        SendMessageW(g_hList, LB_SETITEMDATA, added, (LPARAM)i);
        added++;
    }

    wchar_t status[128];
    swprintf_s(status, L"Found %d processes  |  Showing %d", (int)g_procList.size(), added);
    SetStatus(status, C_TEXT_DIM);
}

// ─────────────────────────────────────────────────────────────────────────────
// Dump thread
// ─────────────────────────────────────────────────────────────────────────────

struct DumpThreadParams {
    DWORD        pid;
    std::wstring procName;
    std::wstring outPath;
};

static void DumpThread(DumpThreadParams params) {
    DumpResult result;

    auto progress = [&](const std::wstring& msg, int pct) {
        // Send progress to main window (thread-safe)
        wchar_t* copy = new wchar_t[msg.size() + 1];
        wcscpy_s(copy, msg.size() + 1, msg.c_str());
        PostMessageW(g_hWnd, WM_DUMP_PROGRESS, (WPARAM)pct, (LPARAM)copy);
    };

    bool ok = DumpProcess(params.pid, result, progress);

    if (ok) {
        bool wrote = WriteOffsets(result, params.outPath);
        // Send result text to main window
        std::wstring* resultCopy = new std::wstring(
            wrote ? params.outPath : L"ERROR_WRITE");
        PostMessageW(g_hWnd, WM_DUMP_DONE, (WPARAM)ok, (LPARAM)resultCopy);
    } else {
        std::wstring* resultCopy = new std::wstring(L"ERROR_OPEN");
        PostMessageW(g_hWnd, WM_DUMP_DONE, (WPARAM)0, (LPARAM)resultCopy);
    }
}

static void StartDump() {
    if (g_dumping) return;

    int sel = (int)SendMessageW(g_hList, LB_GETCURSEL, 0, 0);
    if (sel < 0) {
        SetStatus(L"  Select a process first!", C_ERR);
        return;
    }

    int idx = (int)SendMessageW(g_hList, LB_GETITEMDATA, sel, 0);
    if (idx < 0 || idx >= (int)g_procList.size()) return;

    DWORD pid = g_procList[idx].pid;
    std::wstring name = g_procList[idx].name;
    std::wstring outPath = GetOutputPath(name);

    g_dumping = true;
    g_lastOutputPath = outPath;

    EnableWindow(g_hBtnDump, FALSE);
    EnableWindow(g_hBtnRefresh, FALSE);
    SendMessageW(g_hProgress, PBM_SETPOS, 0, 0);

    LogAppend(L"");
    LogAppend(L"▶  Starting dump: " + name + L" [PID: " + std::to_wstring(pid) + L"]");
    LogAppend(L"   Output → " + outPath);
    LogAppend(L"");

    DumpThreadParams params;
    params.pid      = pid;
    params.procName = name;
    params.outPath  = outPath;

    std::thread t(DumpThread, params);
    t.detach();
}

// ─────────────────────────────────────────────────────────────────────────────
// Custom drawing helpers
// ─────────────────────────────────────────────────────────────────────────────

static void FillRectColor(HDC hdc, RECT r, COLORREF col) {
    HBRUSH br = CreateSolidBrush(col);
    FillRect(hdc, &r, br);
    DeleteObject(br);
}

static void DrawRoundRect(HDC hdc, RECT r, int rx, int ry, COLORREF fillCol, COLORREF borderCol, int borderW = 1) {
    HBRUSH fill   = CreateSolidBrush(fillCol);
    HPEN   border = CreatePen(PS_SOLID, borderW, borderCol);
    HBRUSH oldBr  = (HBRUSH)SelectObject(hdc, fill);
    HPEN   oldPen = (HPEN)SelectObject(hdc, border);
    RoundRect(hdc, r.left, r.top, r.right, r.bottom, rx, ry);
    SelectObject(hdc, oldBr);
    SelectObject(hdc, oldPen);
    DeleteObject(fill);
    DeleteObject(border);
}

static void DrawTextCentered(HDC hdc, const wchar_t* text, RECT r, COLORREF col, HFONT font) {
    HFONT oldFont = (HFONT)SelectObject(hdc, font);
    SetTextColor(hdc, col);
    SetBkMode(hdc, TRANSPARENT);
    DrawTextW(hdc, text, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(hdc, oldFont);
}

// Custom button draw (OwnerDraw)
static void DrawButton(LPDRAWITEMSTRUCT dis) {
    HWND hBtn = dis->hwndItem;
    HDC  hdc  = dis->hDC;
    RECT r    = dis->rcItem;

    bool hovered  = (g_hoverBtn == hBtn);
    bool pressed  = (dis->itemState & ODS_SELECTED) != 0;
    bool disabled = (dis->itemState & ODS_DISABLED) != 0;

    COLORREF bg, txt, border;
    if (disabled) {
        bg = RGB(22, 22, 40); txt = C_TEXT_DIM; border = C_BORDER;
    } else if (pressed) {
        bg = C_BTN_ACT; txt = C_TEXT_BRIGHT; border = C_ACCENT;
    } else if (hovered) {
        bg = C_BTN_HOV; txt = C_TEXT_BRIGHT; border = C_ACCENT;
    } else {
        bg = C_BTN; txt = C_TEXT; border = C_BORDER;
    }

    DrawRoundRect(hdc, r, 6, 6, bg, border, hovered || pressed ? 2 : 1);

    // Draw text
    wchar_t label[128] = {};
    GetWindowTextW(hBtn, label, 128);
    DrawTextCentered(hdc, label, r, txt, g_fontMain);
}

// ─────────────────────────────────────────────────────────────────────────────
// WndProc
// ─────────────────────────────────────────────────────────────────────────────

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {

    case WM_CREATE: {
        // Create brushes & fonts
        g_brBg     = CreateSolidBrush(C_BG);
        g_brPanel  = CreateSolidBrush(C_PANEL);
        g_brPanel2 = CreateSolidBrush(C_PANEL2);
        g_brBtn    = CreateSolidBrush(C_BTN);

        g_fontTitle = CreateFontW(22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        g_fontMain  = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        g_fontMono  = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, FIXED_PITCH, L"Consolas");
        g_fontSmall = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");

        RECT rcClient;
        GetClientRect(hWnd, &rcClient);
        int W = rcClient.right, H = rcClient.bottom;

        // ── Filter / search ─────────────────────────────────────────────────
        g_hFilter = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            10, 55, 295, 26, hWnd, (HMENU)IDC_EDIT_FILTER, nullptr, nullptr);
        SendMessageW(g_hFilter, WM_SETFONT, (WPARAM)g_fontMain, TRUE);
        SendMessageW(g_hFilter, EM_SETCUEBANNER, 0, (LPARAM)L"  Filter processes...");

        // ── Process listbox ──────────────────────────────────────────────────
        g_hList = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY |
            LBS_HASSTRINGS | LBS_NOINTEGRALHEIGHT | LBS_OWNERDRAWFIXED,
            10, 88, 295, H - 200, hWnd, (HMENU)IDC_LIST_PROC, nullptr, nullptr);
        SendMessageW(g_hList, LB_SETITEMHEIGHT, 0, 22);
        SendMessageW(g_hList, WM_SETFONT, (WPARAM)g_fontMono, TRUE);

        // ── Log area ─────────────────────────────────────────────────────────
        g_hLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE |
            ES_AUTOVSCROLL | ES_READONLY | ES_WANTRETURN,
            315, 88, W - 325, H - 200, hWnd, (HMENU)IDC_EDIT_LOG, nullptr, nullptr);
        SendMessageW(g_hLog, WM_SETFONT, (WPARAM)g_fontMono, TRUE);

        // ── Progress bar ─────────────────────────────────────────────────────
        g_hProgress = CreateWindowExW(0, PROGRESS_CLASSW, L"",
            WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
            10, H - 105, W - 20, 8, hWnd, (HMENU)IDC_PROGRESS, nullptr, nullptr);
        SendMessageW(g_hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessageW(g_hProgress, PBM_SETBARCOLOR, 0, (LPARAM)C_ACCENT);
        SendMessageW(g_hProgress, PBM_SETBKCOLOR,  0, (LPARAM)C_PANEL);

        // ── Buttons ──────────────────────────────────────────────────────────
        g_hBtnRefresh = CreateWindowExW(0, L"BUTTON", L"⟳  REFRESH",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            10, H - 90, 140, 36, hWnd, (HMENU)IDC_BTN_REFRESH, nullptr, nullptr);

        g_hBtnDump = CreateWindowExW(0, L"BUTTON", L"⬇  DUMP OFFSETS",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            155, H - 90, 150, 36, hWnd, (HMENU)IDC_BTN_DUMP, nullptr, nullptr);

        g_hBtnClear = CreateWindowExW(0, L"BUTTON", L"✕  CLEAR",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            315, H - 90, 130, 36, hWnd, (HMENU)IDC_BTN_CLEAR, nullptr, nullptr);

        g_hBtnOpen = CreateWindowExW(0, L"BUTTON", L"📂  OPEN OUTPUT",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            455, H - 90, 150, 36, hWnd, (HMENU)IDC_BTN_OPENFOLDER, nullptr, nullptr);

        // ── Status bar ───────────────────────────────────────────────────────
        g_hStatus = CreateWindowExW(0, L"STATIC", L"  Ready.",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            0, H - 26, W, 26, hWnd, (HMENU)IDC_STATUS, nullptr, nullptr);
        SendMessageW(g_hStatus, WM_SETFONT, (WPARAM)g_fontSmall, TRUE);

        // Enable dark mode title bar (Windows 10+)
        BOOL dark = TRUE;
        DwmSetWindowAttribute(hWnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark, sizeof(dark));

        RefreshProcessList();
        LogAppend(L"  ╔══════════════════════════════════════════╗");
        LogAppend(L"  ║       Process Memory Offset Dumper       ║");
        LogAppend(L"  ║      Select a process → Dump Offsets     ║");
        LogAppend(L"  ╚══════════════════════════════════════════╝");
        LogAppend(L"");
        LogAppend(L"  Output path: " + GetOutputPath());
        return 0;
    }

    case WM_SIZE: {
        int W = LOWORD(lParam), H = HIWORD(lParam);
        if (W < 100 || H < 100) break;
        SetWindowPos(g_hFilter,   nullptr, 10, 55, 295, 26, SWP_NOZORDER);
        SetWindowPos(g_hList,     nullptr, 10, 88, 295, H - 200, SWP_NOZORDER);
        SetWindowPos(g_hLog,      nullptr, 315, 88, W - 325, H - 200, SWP_NOZORDER);
        SetWindowPos(g_hProgress, nullptr, 10, H - 105, W - 20, 8, SWP_NOZORDER);
        SetWindowPos(g_hBtnRefresh,nullptr,10,  H - 90, 140, 36, SWP_NOZORDER);
        SetWindowPos(g_hBtnDump,  nullptr, 155, H - 90, 150, 36, SWP_NOZORDER);
        SetWindowPos(g_hBtnClear, nullptr, 315, H - 90, 130, 36, SWP_NOZORDER);
        SetWindowPos(g_hBtnOpen,  nullptr, 455, H - 90, 150, 36, SWP_NOZORDER);
        SetWindowPos(g_hStatus,   nullptr, 0,   H - 26, W,   26, SWP_NOZORDER);
        InvalidateRect(hWnd, nullptr, TRUE);
        break;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        RECT rcClient;
        GetClientRect(hWnd, &rcClient);
        int W = rcClient.right, H = rcClient.bottom;

        // Background
        FillRectColor(hdc, rcClient, C_BG);

        // Header gradient bar
        RECT hdrRect = {0, 0, W, 48};
        FillRectColor(hdc, hdrRect, C_PANEL);

        // Accent strip at top
        RECT accentLine = {0, 0, W, 3};
        FillRectColor(hdc, accentLine, C_ACCENT);

        // Title text
        HFONT oldFont = (HFONT)SelectObject(hdc, g_fontTitle);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, C_TEXT_BRIGHT);
        RECT titleRect = {12, 0, W / 2, 48};
        DrawTextW(hdc, L"Process Offset Dumper", -1, &titleRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        // Subtitle right side
        SelectObject(hdc, g_fontSmall);
        SetTextColor(hdc, C_TEXT_DIM);
        RECT subRect = {W / 2, 0, W - 12, 48};
        DrawTextW(hdc, L"PE · Exports · Sections · Patterns → offsets.txt", -1, &subRect, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        SelectObject(hdc, oldFont);

        // Section labels
        HFONT labelFont = (HFONT)SelectObject(hdc, g_fontSmall);
        SetTextColor(hdc, C_ACCENT);
        RECT lbl1 = {10, 52, 200, 70};
        DrawTextW(hdc, L"PROCESSES", -1, &lbl1, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        RECT lbl2 = {315, 52, 600, 70};
        DrawTextW(hdc, L"OUTPUT LOG", -1, &lbl2, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        SelectObject(hdc, labelFont);

        // Left panel background
        RECT leftPanel = {8, 84, 308, H - 196};
        DrawRoundRect(hdc, leftPanel, 4, 4, C_PANEL, C_BORDER);

        // Right panel background
        RECT rightPanel = {312, 84, W - 10, H - 196};
        DrawRoundRect(hdc, rightPanel, 4, 4, C_PANEL, C_BORDER);

        // Progress label
        RECT progLabel = {10, H - 118, 200, H - 108};
        SelectObject(hdc, g_fontSmall);
        SetTextColor(hdc, C_TEXT_DIM);
        SetBkMode(hdc, TRANSPARENT);
        DrawTextW(hdc, L"DUMP PROGRESS", -1, &progLabel, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        SelectObject(hdc, oldFont);

        // Status bar background
        RECT statusBg = {0, H - 28, W, H};
        FillRectColor(hdc, statusBg, C_PANEL);
        // Status border line
        RECT statusLine = {0, H - 28, W, H - 27};
        FillRectColor(hdc, statusLine, C_BORDER);

        // Status text (manual draw because STATIC can't do colors easily)
        wchar_t statusTxt[256] = {};
        GetWindowTextW(g_hStatus, statusTxt, 256);
        SelectObject(hdc, g_fontSmall);
        SetTextColor(hdc, C_TEXT_DIM);
        SetBkMode(hdc, TRANSPARENT);
        RECT statusTxtRect = {8, H - 27, W - 8, H};
        DrawTextW(hdc, statusTxt, -1, &statusTxtRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        EndPaint(hWnd, &ps);
        return 0;
    }

    // Paint the listbox items
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lParam;
        if (dis->hwndItem == g_hList) {
            HDC hdc = dis->hDC;
            RECT r  = dis->rcItem;

            bool selected = (dis->itemState & ODS_SELECTED) != 0;
            bool focused  = (dis->itemState & ODS_FOCUS) != 0;

            // Row background
            COLORREF bgCol = selected ? C_SEL_BG : (dis->itemID % 2 == 0 ? C_PANEL : C_PANEL2);
            FillRectColor(hdc, r, bgCol);

            if (dis->itemID == LB_ERR) break;

            wchar_t text[256] = {};
            SendMessageW(dis->hwndItem, LB_GETTEXT, dis->itemID, (LPARAM)text);

            // Left accent bar for selected
            if (selected) {
                RECT accent = {r.left, r.top, r.left + 3, r.bottom};
                FillRectColor(hdc, accent, C_ACCENT);
            }

            HFONT oldFont = (HFONT)SelectObject(hdc, g_fontMono);
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, selected ? C_SEL_TXT : C_TEXT);
            RECT textRect = {r.left + 8, r.top, r.right, r.bottom};
            DrawTextW(hdc, text, -1, &textRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            SelectObject(hdc, oldFont);

            // Focus rect
            if (focused && selected)
                DrawFocusRect(hdc, &r);
            return 0;
        }
        if (dis->hwndItem == g_hBtnRefresh || dis->hwndItem == g_hBtnDump ||
            dis->hwndItem == g_hBtnClear   || dis->hwndItem == g_hBtnOpen) {
            DrawButton(dis);
            return 0;
        }
        break;
    }

    // Color listbox / edit backgrounds
    case WM_CTLCOLORLISTBOX: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, C_TEXT);
        SetBkColor(hdc, C_PANEL);
        return (LRESULT)g_brPanel;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, C_TEXT);
        SetBkColor(hdc, C_PANEL);
        return (LRESULT)g_brPanel;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, C_TEXT_DIM);
        SetBkColor(hdc, C_BG);
        return (LRESULT)g_brBg;
    }

    // Hover tracking for buttons
    case WM_MOUSEMOVE: {
        POINT pt = {GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        HWND under = ChildWindowFromPoint(hWnd, pt);
        if (under != g_hoverBtn) {
            HWND old = g_hoverBtn;
            g_hoverBtn = under;
            if (old) InvalidateRect(old, nullptr, TRUE);
            if (under) InvalidateRect(under, nullptr, TRUE);
        }
        break;
    }

    case WM_COMMAND: {
        WORD id  = LOWORD(wParam);
        WORD evt = HIWORD(wParam);

        if (id == IDC_BTN_REFRESH) {
            RefreshProcessList();
        } else if (id == IDC_BTN_DUMP) {
            StartDump();
        } else if (id == IDC_BTN_CLEAR) {
            SetWindowTextW(g_hLog, L"");
        } else if (id == IDC_BTN_OPENFOLDER) {
            std::wstring path = GetOutputPath();
            // Open folder containing the file
            for (int i = (int)path.size() - 1; i >= 0; i--) {
                if (path[i] == L'\\') { path.resize(i); break; }
            }
            ShellExecuteW(nullptr, L"explore", path.c_str(), nullptr, nullptr, SW_SHOW);
        } else if (id == IDC_EDIT_FILTER && evt == EN_CHANGE) {
            RefreshProcessList();
        } else if (id == IDC_LIST_PROC && evt == LBN_DBLCLK) {
            StartDump();
        }
        break;
    }

    case WM_DUMP_PROGRESS: {
        int pct = (int)wParam;
        wchar_t* msg = (wchar_t*)lParam;
        if (msg) {
            SetStatus(std::wstring(L"  ") + msg, C_TEXT_DIM);
            delete[] msg;
        }
        SendMessageW(g_hProgress, PBM_SETPOS, pct, 0);
        break;
    }

    case WM_DUMP_DONE: {
        bool ok = (bool)wParam;
        std::wstring* pathPtr = (std::wstring*)lParam;
        std::wstring outPath = pathPtr ? *pathPtr : L"";
        delete pathPtr;

        g_dumping = false;
        EnableWindow(g_hBtnDump, TRUE);
        EnableWindow(g_hBtnRefresh, TRUE);

        if (!ok || outPath == L"ERROR_OPEN") {
            LogAppend(L"  ✕  FAILED: Could not open process. Try running as Administrator.");
            SetStatus(L"  Dump failed. Run as Administrator?", C_ERR);
        } else if (outPath == L"ERROR_WRITE") {
            LogAppend(L"  ✕  Dump OK but could not write file.");
            SetStatus(L"  Could not write offsets.txt", C_ERR);
        } else {
            LogAppend(L"  ✓  Dump complete!");
            LogAppend(L"  →  Saved to: " + outPath);
            SetStatus(L"  ✓  Done! offsets.txt saved → " + outPath, C_OK);
        }
        SendMessageW(g_hProgress, PBM_SETPOS, 100, 0);
        break;
    }

    case WM_KEYDOWN:
        if (wParam == VK_F5) RefreshProcessList();
        break;

    case WM_ERASEBKGND:
        return 1; // Prevent flicker

    case WM_GETMINMAXINFO: {
        LPMINMAXINFO mmi = (LPMINMAXINFO)lParam;
        mmi->ptMinTrackSize = {720, 520};
        break;
    }

    case WM_DESTROY:
        DeleteObject(g_brBg);
        DeleteObject(g_brPanel);
        DeleteObject(g_brPanel2);
        DeleteObject(g_brBtn);
        DeleteObject(g_fontTitle);
        DeleteObject(g_fontMain);
        DeleteObject(g_fontMono);
        DeleteObject(g_fontSmall);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ─────────────────────────────────────────────────────────────────────────────
// WinMain
// ─────────────────────────────────────────────────────────────────────────────
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    EnableDebugPrivilege();
    // Init common controls
    INITCOMMONCONTROLSEX icex = {sizeof(icex), ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ProcessDumperWnd";
    wc.hIcon         = LoadIconW(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    g_hWnd = CreateWindowExW(
        WS_EX_APPWINDOW,
        L"ProcessDumperWnd",
        L"Process Offset Dumper  —  v1.0",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        920, 620,
        nullptr, nullptr, hInstance, nullptr);

    if (!g_hWnd) return 1;

    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);

    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}


