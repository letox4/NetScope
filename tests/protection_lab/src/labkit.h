/* labkit.h — kit común de los ejecutables de laboratorio de protecciones.
 *
 * Cada ejecutable es INDEPENDIENTE (un .exe por mecanismo), usa APIs reales de
 * Windows y habla el mismo protocolo:
 *   stdout: una línea JSON por evento {"event":..., "t":<ms>, "pid":..., ...}
 *   stdin : comandos de texto (exit, status, query, free, realloc, ro, rw, ...)
 * Opciones comunes:
 *   --on-detect=report|exit|terminate|crash|failfast   acción ante una detección
 *   --grace-ms=N        espera antes de actuar        --interval-ms=N  periodo
 *   --net               tráfico TCP loopback propio (send/recv de ws2_32)
 *   --max-seconds=N     vigilante: el proceso se cierra solo (por defecto 300)
 * Estos programas SOLO se detectan a sí mismos: no tocan procesos de terceros.
 */
#pragma once
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

#ifdef _WIN64
#define LK_ARCH "x64"
#else
#define LK_ARCH "x86"
#endif

#define LK_PAGE 4096

enum { LK_REPORT = 0, LK_EXIT, LK_TERMINATE, LK_CRASH, LK_FAILFAST };

typedef struct { const char *name; uintptr_t base; size_t size; } LkRegion;

static LkRegion lk_regions[16];
static int lk_nregions = 0;
static int lk_exec_ok = 1;      /* 0 si el SO impidió crear memoria ejecutable (ProhibitDynamicCode) */
static const char *lk_name = "lab";
static ULONGLONG lk_t0;
static DWORD lk_interval_ms = 50;
static DWORD lk_grace_ms = 0;
static DWORD lk_max_seconds = 300;
static int lk_on_detect = LK_REPORT;
static int lk_net = 0;
static volatile LONG lk_checks = 0, lk_detections = 0;
static volatile LONG lk_net_sent = 0, lk_net_recv = 0;
static int lk_argc;
static char **lk_argv;
static CRITICAL_SECTION lk_cs;
static void (*lk_user_cmd)(const char *line) = NULL;
static void (*lk_user_status)(char *out, size_t n) = NULL;

/* ---------- salida JSON ---------- */
static void lk_esc(char *dst, size_t n, const char *src) {
    size_t o = 0;
    for (; *src && o + 7 < n; src++) {
        unsigned char c = (unsigned char)*src;
        if (c == '"' || c == '\\') { dst[o++] = '\\'; dst[o++] = (char)c; }
        else if (c < 0x20) { o += (size_t)_snprintf(dst + o, n - o, "\\u%04x", c); }
        else dst[o++] = (char)c;
    }
    dst[o] = 0;
}

static void lk_emit(const char *event, const char *fmt, ...) {
    char body[3072], line[3584];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf(body, sizeof body - 1, fmt ? fmt : "", ap);
    va_end(ap);
    body[sizeof body - 1] = 0;
    int n = _snprintf(line, sizeof line - 2,
                      "{\"event\":\"%s\",\"lab\":\"%s\",\"t\":%llu,\"pid\":%lu%s%s}\n",
                      event, lk_name, GetTickCount64() - lk_t0, GetCurrentProcessId(),
                      body[0] ? "," : "", body);
    if (n < 0) n = (int)sizeof line - 2;
    EnterCriticalSection(&lk_cs);
    DWORD w;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), line, (DWORD)n, &w, NULL);
    LeaveCriticalSection(&lk_cs);
}

static void lk_hex(char *dst, const unsigned char *src, size_t n) {
    for (size_t i = 0; i < n; i++) _snprintf(dst + i * 2, 3, "%02x", src[i]);
    dst[n * 2] = 0;
}

static uint64_t lk_fnv(const void *p, size_t n) {
    const unsigned char *b = (const unsigned char *)p;
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= b[i]; h *= 1099511628211ULL; }
    return h;
}

/* ---------- terminación deliberada ---------- */
static const char *lk_action_name(int a) {
    switch (a) {
    case LK_EXIT: return "ExitProcess";
    case LK_TERMINATE: return "TerminateProcess";
    case LK_CRASH: return "AccessViolation";
    case LK_FAILFAST: return "FastFail";
    default: return "none";
    }
}

static void lk_die(int action, const char *why) {
    lk_emit("terminating", "\"method\":\"%s\",\"reason\":\"%s\",\"grace_ms\":%lu",
            lk_action_name(action), why, (unsigned long)lk_grace_ms);
    if (lk_grace_ms) Sleep(lk_grace_ms);
    switch (action) {
    case LK_EXIT: ExitProcess(3); break;
    case LK_TERMINATE: TerminateProcess(GetCurrentProcess(), 4); break;
    case LK_CRASH: *(volatile int *)0 = 1; break;
    case LK_FAILFAST:
#ifdef _MSC_VER
        __fastfail(7);
#else
        RaiseFailFastException(NULL, NULL, 0);
#endif
        break;
    }
    ExitProcess(9);
}

/* Una detección por (mecanismo, clave): se informa una vez y se aplica --on-detect. */
static char lk_seen[96][160];
static int lk_nseen = 0;
static void lk_detect(const char *mech, const char *key, const char *fmt, ...) {
    char id[160], body[2048];
    _snprintf(id, sizeof id, "%s|%s", mech, key ? key : "");
    EnterCriticalSection(&lk_cs);
    for (int i = 0; i < lk_nseen; i++)
        if (strcmp(lk_seen[i], id) == 0) { LeaveCriticalSection(&lk_cs); return; }
    if (lk_nseen < 96) { strncpy(lk_seen[lk_nseen], id, 159); lk_seen[lk_nseen][159] = 0; lk_nseen++; }
    LeaveCriticalSection(&lk_cs);
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf(body, sizeof body - 1, fmt ? fmt : "", ap);
    va_end(ap);
    body[sizeof body - 1] = 0;
    InterlockedIncrement(&lk_detections);
    lk_emit("detect", "\"mech\":\"%s\"%s%s", mech, body[0] ? "," : "", body);
    if (lk_on_detect != LK_REPORT) lk_die(lk_on_detect, mech);
}

/* ---------- regiones de laboratorio ---------- */
static void *lk_alloc(size_t size, DWORD prot) {
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, prot);
}

static void lk_add(const char *name, void *base, size_t size) {
    lk_regions[lk_nregions].name = name;
    lk_regions[lk_nregions].base = (uintptr_t)base;
    lk_regions[lk_nregions].size = size;
    lk_nregions++;
}

static LkRegion *lk_find(const char *name) {
    for (int i = 0; i < lk_nregions; i++)
        if (strcmp(lk_regions[i].name, name) == 0) return &lk_regions[i];
    return NULL;
}

/* Patrón conocido de 64 KB: byte i = (i*31+7) & 0xFF (lo recalcula el cliente). */
static void lk_setup_regions(void) {
    DWORD old;
    unsigned char stub[] = { 0xB8, 0x34, 0x12, 0x00, 0x00, 0xC3 };   /* mov eax,0x1234 ; ret */
    unsigned char *two = (unsigned char *)lk_alloc(2 * LK_PAGE, PAGE_READWRITE);
    memset(two, 'A', LK_PAGE);
    VirtualProtect(two + LK_PAGE, LK_PAGE, PAGE_READONLY, &old);
    lk_add("two", two, 2 * LK_PAGE);

    unsigned char *freeme = (unsigned char *)lk_alloc(16 * LK_PAGE, PAGE_READWRITE);
    memcpy(freeme, "FREEME-DATA", 11);
    lk_add("freeme", freeme, 16 * LK_PAGE);

    unsigned char *flip = (unsigned char *)lk_alloc(LK_PAGE, PAGE_READWRITE);
    memcpy(flip, "FLIP-DATA", 9);
    lk_add("flip", flip, LK_PAGE);

    unsigned char *guard = (unsigned char *)lk_alloc(LK_PAGE, PAGE_READWRITE);
    VirtualProtect(guard, LK_PAGE, PAGE_READWRITE | PAGE_GUARD, &old);
    lk_add("guard", guard, LK_PAGE);

    unsigned char *edge = (unsigned char *)lk_alloc(2 * LK_PAGE, PAGE_READWRITE);
    VirtualProtect(edge + LK_PAGE, LK_PAGE, PAGE_READWRITE | PAGE_GUARD, &old);
    memcpy(edge + LK_PAGE - 8, "EDGE-END", 8);
    lk_add("edge", edge, 2 * LK_PAGE);

    unsigned char *tail = (unsigned char *)lk_alloc(LK_PAGE, PAGE_READWRITE);
    static const unsigned char sc[16] = { 0x78, 0x56, 0x34, 0x12, 0xef, 0xbe, 0xad, 0xde,
                                          'c', 's', 't', 'r', '-', 'o', 'k', 0 };
    memcpy(tail, sc, 16);
    lk_add("tail", tail, LK_PAGE);

    unsigned char *pat = (unsigned char *)lk_alloc(16 * LK_PAGE, PAGE_READWRITE);
    for (size_t i = 0; i < 16 * LK_PAGE; i++) pat[i] = (unsigned char)((i * 31 + 7) & 0xFF);
    lk_add("pattern", pat, 16 * LK_PAGE);

    unsigned char *rx = (unsigned char *)lk_alloc(LK_PAGE, PAGE_READWRITE);
    memcpy(rx, stub, sizeof stub);
    if (!VirtualProtect(rx, LK_PAGE, PAGE_EXECUTE_READ, &old)) lk_exec_ok = 0;   /* ProhibitDynamicCode */
    lk_add("rx", rx, LK_PAGE);

    unsigned char *rwx = (unsigned char *)lk_alloc(LK_PAGE, PAGE_EXECUTE_READWRITE);
    if (!rwx) { rwx = (unsigned char *)lk_alloc(LK_PAGE, PAGE_READWRITE); lk_exec_ok = 0; }
    memcpy(rwx, stub, sizeof stub);
    lk_add("rwx", rwx, LK_PAGE);
}

static void lk_prot_json(char *out, size_t n) {
    size_t o = 0;
    o += (size_t)_snprintf(out + o, n - o, "{");
    for (int i = 0; i < lk_nregions; i++) {
        LkRegion *r = &lk_regions[i];
        size_t pages = r->size / LK_PAGE;
        for (size_t p = 0; p < pages && o + 64 < n; p++) {
            MEMORY_BASIC_INFORMATION mbi;
            memset(&mbi, 0, sizeof mbi);
            VirtualQuery((void *)(r->base + p * LK_PAGE), &mbi, sizeof mbi);
            o += (size_t)_snprintf(out + o, n - o, "%s\"%s.%u\":[%lu,%lu]",
                                   o > 1 ? "," : "", r->name, (unsigned)p,
                                   (unsigned long)mbi.Protect, (unsigned long)mbi.State);
        }
    }
    _snprintf(out + o, n - o, "}");
}

/* ---------- tráfico de red propio (para probar el agente de red) ---------- */
static volatile unsigned short lk_net_port = 0;

static DWORD WINAPI lk_net_server(LPVOID unused) {
    (void)unused;
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(ls, (struct sockaddr *)&a, sizeof a);
    int al = sizeof a;
    getsockname(ls, (struct sockaddr *)&a, &al);
    lk_net_port = ntohs(a.sin_port);
    listen(ls, 1);
    SOCKET c = accept(ls, NULL, NULL);
    char buf[256];
    for (;;) {
        int n = recv(c, buf, sizeof buf, 0);
        if (n <= 0) break;
        send(c, buf, n, 0);
    }
    return 0;
}

static DWORD WINAPI lk_net_client(LPVOID unused) {
    (void)unused;
    while (!lk_net_port) Sleep(10);
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(lk_net_port);
    if (connect(s, (struct sockaddr *)&a, sizeof a) != 0) return 1;
    char msg[64], buf[64];
    for (int i = 0;; i++) {
        int len = _snprintf(msg, sizeof msg, "NETSCOPE-LAB-PING-%d", i);
        if (send(s, msg, len, 0) <= 0) break;
        InterlockedIncrement(&lk_net_sent);
        if (recv(s, buf, sizeof buf, 0) <= 0) break;
        InterlockedIncrement(&lk_net_recv);
        Sleep(100);
    }
    return 0;
}

static void lk_start_net(void) {
    WSADATA wd;
    WSAStartup(MAKEWORD(2, 2), &wd);
    CreateThread(NULL, 0, lk_net_server, NULL, 0, NULL);
    CreateThread(NULL, 0, lk_net_client, NULL, 0, NULL);
}

/* ---------- comandos por stdin / vigilante ---------- */
static void lk_status(void) {
    char extra[1024] = "";
    if (lk_user_status) lk_user_status(extra, sizeof extra);
    lk_emit("status", "\"checks\":%ld,\"detections\":%ld,\"net_sent\":%ld,\"net_recv\":%ld%s%s",
            lk_checks, lk_detections, lk_net_sent, lk_net_recv, extra[0] ? "," : "", extra);
}

static DWORD WINAPI lk_cmd_thread(LPVOID unused) {
    (void)unused;
    char line[256];
    size_t n = 0;
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    for (;;) {
        char ch;
        DWORD got = 0;
        if (!in || in == INVALID_HANDLE_VALUE) return 0;
        if (!ReadFile(in, &ch, 1, &got, NULL) || got == 0) { Sleep(200); continue; }
        if (ch == '\r') continue;
        if (ch != '\n') { if (n < sizeof line - 1) line[n++] = ch; continue; }
        line[n] = 0; n = 0;
        if (!strcmp(line, "exit")) ExitProcess(0);
        else if (!strcmp(line, "status")) lk_status();
        else if (!strcmp(line, "query")) {
            char buf[6144];
            lk_prot_json(buf, sizeof buf);
            lk_emit("query", "\"prot\":%s", buf);
        } else if (!strcmp(line, "free")) {
            LkRegion *r = lk_find("freeme");
            lk_emit("ack", "\"cmd\":\"free\",\"ok\":%d", VirtualFree((void *)r->base, 0, MEM_RELEASE) ? 1 : 0);
        } else if (!strcmp(line, "realloc")) {
            LkRegion *r = lk_find("freeme");
            void *p = VirtualAlloc((void *)r->base, r->size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (p) memcpy(p, "REALLOC-DATA", 12);
            lk_emit("ack", "\"cmd\":\"realloc\",\"ok\":%d", p ? 1 : 0);
        } else if (!strcmp(line, "ro") || !strcmp(line, "rw")) {
            LkRegion *r = lk_find("flip");
            DWORD old;
            BOOL ok = VirtualProtect((void *)r->base, LK_PAGE, line[1] == 'o' ? PAGE_READONLY : PAGE_READWRITE, &old);
            lk_emit("ack", "\"cmd\":\"%s\",\"ok\":%d", line, ok ? 1 : 0);
        } else if (lk_user_cmd) lk_user_cmd(line);
    }
}

static DWORD WINAPI lk_watchdog(LPVOID unused) {
    (void)unused;
    Sleep(lk_max_seconds * 1000);
    lk_emit("watchdog", "\"max_seconds\":%lu", (unsigned long)lk_max_seconds);
    ExitProcess(5);
    return 0;
}

/* ---------- opciones ---------- */
static const char *lk_opt(const char *name) {
    size_t l = strlen(name);
    for (int i = 1; i < lk_argc; i++)
        if (!strncmp(lk_argv[i], name, l)) {
            if (lk_argv[i][l] == '=') return lk_argv[i] + l + 1;
            if (lk_argv[i][l] == 0) return "";
        }
    return NULL;
}

static int lk_optint(const char *name, int def) {
    const char *v = lk_opt(name);
    return (v && *v) ? atoi(v) : def;
}

static void lk_init(int argc, char **argv, const char *name) {
    lk_argc = argc;
    lk_argv = argv;
    lk_name = name;
    lk_t0 = GetTickCount64();
    InitializeCriticalSection(&lk_cs);
    const char *od = lk_opt("--on-detect");
    if (od) {
        if (!strcmp(od, "exit")) lk_on_detect = LK_EXIT;
        else if (!strcmp(od, "terminate")) lk_on_detect = LK_TERMINATE;
        else if (!strcmp(od, "crash")) lk_on_detect = LK_CRASH;
        else if (!strcmp(od, "failfast")) lk_on_detect = LK_FAILFAST;
    }
    lk_grace_ms = (DWORD)lk_optint("--grace-ms", 0);
    lk_interval_ms = (DWORD)lk_optint("--interval-ms", 50);
    lk_max_seconds = (DWORD)lk_optint("--max-seconds", 300);
    lk_net = lk_opt("--net") != NULL;
    int startup = lk_optint("--startup-delay-ms", 0);
    if (startup) Sleep((DWORD)startup);
}

static void lk_ready(const char *extra_json) {
    char names[2048];
    size_t o = 0;
    names[0] = 0;
    for (int i = 0; i < lk_nregions; i++)
        o += (size_t)_snprintf(names + o, sizeof names - o, "%s\"%s\":%llu", i ? "," : "",
                               lk_regions[i].name, (unsigned long long)lk_regions[i].base);
    char exe[MAX_PATH];
    GetModuleFileNameA(NULL, exe, MAX_PATH);
    char esc[2 * MAX_PATH];
    lk_esc(esc, sizeof esc, exe);
    if (lk_net) lk_start_net();
    lk_emit("ready", "\"arch\":\"%s\",\"bits\":%d,\"exe\":\"%s\",\"on_detect\":\"%s\",\"net\":%d,\"exec_regions_ok\":%d,"
                     "\"regions\":{%s}%s%s",
            LK_ARCH, (int)(sizeof(void *) * 8), esc, lk_action_name(lk_on_detect), lk_net, lk_exec_ok, names,
            extra_json && extra_json[0] ? "," : "", extra_json ? extra_json : "");
    CreateThread(NULL, 0, lk_cmd_thread, NULL, 0, NULL);
    CreateThread(NULL, 0, lk_watchdog, NULL, 0, NULL);
}

/* ---------- utilidades de módulos ---------- */
static int lk_is_system_path(const char *path) {
    char win[MAX_PATH];
    UINT n = GetWindowsDirectoryA(win, MAX_PATH);
    return n && _strnicmp(path, win, n) == 0;
}

/* ============================================================
 *  DETECTORES (cada uno informa vía lk_detect con su evidencia)
 * ============================================================ */

/* --- banderas de depuración --- */
typedef LONG (NTAPI *LkNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static LkNtQueryInformationProcess lk_ntq(void) {
    static LkNtQueryInformationProcess f;
    if (!f) f = (LkNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    return f;
}

static void lk_check_isdebuggerpresent(void) {
    InterlockedIncrement(&lk_checks);
    if (IsDebuggerPresent()) lk_detect("IsDebuggerPresent", "", "\"value\":1");
}

static void lk_check_remote(void) {
    BOOL dbg = FALSE;
    InterlockedIncrement(&lk_checks);
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg) && dbg)
        lk_detect("CheckRemoteDebuggerPresent", "", "\"value\":1");
}

static void lk_check_ntquery(void) {
    LkNtQueryInformationProcess q = lk_ntq();
    InterlockedIncrement(&lk_checks);
    if (!q) return;
    ULONG_PTR port = 0;
    HANDLE obj = NULL;
    ULONG flags = 1;
    LONG s1 = q(GetCurrentProcess(), 7, &port, sizeof port, NULL);          /* ProcessDebugPort */
    LONG s2 = q(GetCurrentProcess(), 0x1E, &obj, sizeof obj, NULL);         /* ProcessDebugObjectHandle */
    LONG s3 = q(GetCurrentProcess(), 0x1F, &flags, sizeof flags, NULL);     /* ProcessDebugFlags */
    if (s1 == 0 && port != 0)
        lk_detect("NtQueryInformationProcess.DebugPort", "", "\"value\":%llu", (unsigned long long)port);
    if (s2 == 0 && obj != NULL)
        lk_detect("NtQueryInformationProcess.DebugObjectHandle", "", "\"status\":%ld", s2);
    if (s3 == 0 && flags == 0)
        lk_detect("NtQueryInformationProcess.DebugFlags", "", "\"value\":0");
}

static void lk_check_peb(void) {
    InterlockedIncrement(&lk_checks);
#ifdef _WIN64
    unsigned char *peb = (unsigned char *)__readgsqword(0x60);
#else
    unsigned char *peb = (unsigned char *)__readfsdword(0x30);
#endif
    if (peb[2]) lk_detect("PEB.BeingDebugged", "", "\"value\":%d", peb[2]);
}

/* --- integridad de prólogos (hooks inline) --- */
typedef struct { const char *mod, *fn; unsigned char *addr; unsigned char base[32]; int ok; } LkHook;
static LkHook lk_hooks[] = {
    { "ws2_32.dll", "send" }, { "ws2_32.dll", "recv" }, { "ws2_32.dll", "connect" },
    { "ws2_32.dll", "WSASend" }, { "ws2_32.dll", "WSARecv" }, { "ws2_32.dll", "sendto" },
    { "ws2_32.dll", "recvfrom" }, { "ws2_32.dll", "socket" }, { "ws2_32.dll", "closesocket" },
    { "kernel32.dll", "LoadLibraryW" }, { "kernel32.dll", "CreateFileW" },
    { "ntdll.dll", "NtQueryInformationProcess" }, { "ntdll.dll", "NtProtectVirtualMemory" },
    { "kernelbase.dll", "IsDebuggerPresent" },
};
#define LK_NHOOKS ((int)(sizeof lk_hooks / sizeof lk_hooks[0]))

static void lk_hooks_baseline(void) {
    LoadLibraryA("ws2_32.dll");
    LoadLibraryA("winhttp.dll");
    LoadLibraryA("wininet.dll");
    for (int i = 0; i < LK_NHOOKS; i++) {
        HMODULE m = GetModuleHandleA(lk_hooks[i].mod);
        FARPROC f = m ? GetProcAddress(m, lk_hooks[i].fn) : NULL;
        if (!f) continue;
        lk_hooks[i].addr = (unsigned char *)f;
        memcpy(lk_hooks[i].base, f, 32);
        lk_hooks[i].ok = 1;
    }
}

static void lk_check_hooks(void) {
    InterlockedIncrement(&lk_checks);
    for (int i = 0; i < LK_NHOOKS; i++) {
        if (!lk_hooks[i].ok) continue;
        unsigned char cur[32];
        memcpy(cur, lk_hooks[i].addr, 32);
        if (memcmp(cur, lk_hooks[i].base, 32) == 0) continue;
        int d = 0;
        while (d < 32 && cur[d] == lk_hooks[i].base[d]) d++;
        char o[65], n[65];
        lk_hex(o, lk_hooks[i].base, 16);
        lk_hex(n, cur, 16);
        char key[96];
        _snprintf(key, sizeof key, "%s!%s", lk_hooks[i].mod, lk_hooks[i].fn);
        lk_detect("inline-hook", key,
                  "\"module\":\"%s\",\"function\":\"%s\",\"address\":%llu,\"first_diff\":%d,"
                  "\"original\":\"%s\",\"current\":\"%s\"",
                  lk_hooks[i].mod, lk_hooks[i].fn, (unsigned long long)(uintptr_t)lk_hooks[i].addr, d, o, n);
    }
}

/* --- hash de las secciones ejecutables de la propia imagen --- */
static uint64_t lk_text_base_hash = 0;

static uint64_t lk_text_hash(void) {
    unsigned char *base = (unsigned char *)GetModuleHandleA(NULL);
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        size_t n = sec[i].Misc.VirtualSize;
        const unsigned char *p = base + sec[i].VirtualAddress;
        for (size_t k = 0; k < n; k++) { h ^= p[k]; h *= 1099511628211ULL; }
    }
    return h;
}

static void lk_check_text(void) {
    InterlockedIncrement(&lk_checks);
    uint64_t h = lk_text_hash();
    if (h != lk_text_base_hash)
        lk_detect("code-integrity-hash", "", "\"baseline\":\"%016llx\",\"current\":\"%016llx\"",
                  (unsigned long long)lk_text_base_hash, (unsigned long long)h);
}

/* --- regiones ejecutables propias (RX y RWX) --- */
static uint64_t lk_exec_base[2];
static const char *lk_exec_names[2] = { "rx", "rwx" };

static void lk_exec_baseline(void) {
    for (int i = 0; i < 2; i++) {
        LkRegion *r = lk_find(lk_exec_names[i]);
        lk_exec_base[i] = lk_fnv((void *)r->base, 64);
    }
}

static void lk_check_exec(void) {
    InterlockedIncrement(&lk_checks);
    for (int i = 0; i < 2; i++) {
        LkRegion *r = lk_find(lk_exec_names[i]);
        uint64_t h = lk_fnv((void *)r->base, 64);
        if (h != lk_exec_base[i])
            lk_detect("executable-memory-change", lk_exec_names[i],
                      "\"region\":\"%s\",\"address\":%llu,\"baseline\":\"%016llx\",\"current\":\"%016llx\"",
                      lk_exec_names[i], (unsigned long long)r->base,
                      (unsigned long long)lk_exec_base[i], (unsigned long long)h);
    }
}

/* --- artefactos de instrumentación Frida (solo detección en el propio proceso) --- */
static const unsigned char lk_k = 0x5A;           /* patrones ofuscados: nunca en claro en memoria */
static const unsigned char lk_p_frida[] = { 'f' ^ 0x5A, 'r' ^ 0x5A, 'i' ^ 0x5A, 'd' ^ 0x5A, 'a' ^ 0x5A };
static const unsigned char lk_p_gumjs[] = { 'g' ^ 0x5A, 'u' ^ 0x5A, 'm' ^ 0x5A, '-' ^ 0x5A, 'j' ^ 0x5A, 's' ^ 0x5A };
static const unsigned char lk_p_gmain[] = { 'g' ^ 0x5A, 'm' ^ 0x5A, 'a' ^ 0x5A, 'i' ^ 0x5A, 'n' ^ 0x5A };
static const unsigned char lk_p_gdbus[] = { 'g' ^ 0x5A, 'd' ^ 0x5A, 'b' ^ 0x5A, 'u' ^ 0x5A, 's' ^ 0x5A };

static int lk_name_matches(const char *s, const unsigned char *enc, size_t n) {
    size_t l = strlen(s);
    for (size_t i = 0; i + n <= l; i++) {
        size_t k = 0;
        while (k < n && (unsigned char)tolower((unsigned char)s[i + k]) == (enc[k] ^ lk_k)) k++;
        if (k == n) return 1;
    }
    return 0;
}

static int lk_name_is_frida(const char *s) {
    return lk_name_matches(s, lk_p_frida, sizeof lk_p_frida)
        || lk_name_matches(s, lk_p_gumjs, sizeof lk_p_gumjs)
        || lk_name_matches(s, lk_p_gmain, sizeof lk_p_gmain)
        || lk_name_matches(s, lk_p_gdbus, sizeof lk_p_gdbus);
}

static void lk_check_frida_modules(void) {
    HMODULE mods[1024];
    DWORD need = 0;
    InterlockedIncrement(&lk_checks);
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof mods, &need)) return;
    for (DWORD i = 0; i < need / sizeof(HMODULE); i++) {
        char nm[MAX_PATH];
        if (GetModuleFileNameExA(GetCurrentProcess(), mods[i], nm, MAX_PATH) && lk_name_is_frida(nm))
            lk_detect("instrumentation:module-name", nm, "\"module\":\"%s\"", nm);
    }
}

typedef HRESULT (WINAPI *LkGetThreadDescription)(HANDLE, PWSTR *);

static void lk_check_frida_threads(int dump) {
    static LkGetThreadDescription gtd;
    if (!gtd) gtd = (LkGetThreadDescription)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "GetThreadDescription");
    InterlockedIncrement(&lk_checks);
    if (!gtd) return;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te;
    te.dwSize = sizeof te;
    char all[1500] = "";
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID != GetCurrentProcessId()) continue;
        HANDLE th = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
        if (!th) continue;
        PWSTR d = NULL;
        if (SUCCEEDED(gtd(th, &d)) && d) {
            char nm[128];
            WideCharToMultiByte(CP_UTF8, 0, d, -1, nm, sizeof nm, NULL, NULL);
            if (nm[0] && strlen(all) + strlen(nm) + 4 < sizeof all) { strcat(all, nm); strcat(all, ";"); }
            if (nm[0] && lk_name_is_frida(nm)) {
                char key[160];
                _snprintf(key, sizeof key, "%s/%lu", nm, te.th32ThreadID);
                lk_detect("instrumentation:thread-name", key, "\"thread\":\"%s\",\"tid\":%lu", nm, te.th32ThreadID);
            }
            LocalFree(d);
        }
        CloseHandle(th);
    }
    CloseHandle(snap);
    if (dump) {
        char esc[1600];
        lk_esc(esc, sizeof esc, all);
        lk_emit("threads", "\"names\":\"%s\"", esc);
    }
}

static void lk_check_frida_pipes(void) {
    WIN32_FIND_DATAA fd;
    InterlockedIncrement(&lk_checks);
    HANDLE h = FindFirstFileA("\\\\.\\pipe\\*", &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (lk_name_is_frida(fd.cFileName))
            lk_detect("instrumentation:named-pipe", fd.cFileName, "\"pipe\":\"%s\"", fd.cFileName);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

static int lk_mem_has(const unsigned char *p, size_t n, const unsigned char *enc, size_t el) {
    if (n < el) return 0;
    for (size_t i = 0; i + el <= n; i++) {
        if ((p[i] ^ lk_k) != enc[0]) continue;
        size_t k = 1;
        while (k < el && (p[i + k] ^ lk_k) == enc[k]) k++;
        if (k == el) return 1;
    }
    return 0;
}

static void lk_check_frida_memory(void) {
    InterlockedIncrement(&lk_checks);
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    unsigned char *a = (unsigned char *)si.lpMinimumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    while ((uintptr_t)a < (uintptr_t)si.lpMaximumApplicationAddress &&
           VirtualQuery(a, &mbi, sizeof mbi)) {
        unsigned char *next = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;
        DWORD pr = mbi.Protect & 0xFF;
        int readable = mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
                       (pr == PAGE_READONLY || pr == PAGE_READWRITE || pr == PAGE_WRITECOPY ||
                        pr == PAGE_EXECUTE_READ || pr == PAGE_EXECUTE_READWRITE);
        /* regiones ejecutables privadas/anónimas (donde vive un agente inyectado) */
        if (readable && mbi.Type == MEM_PRIVATE && mbi.RegionSize <= (256u << 20) &&
            (pr == PAGE_EXECUTE_READ || pr == PAGE_EXECUTE_READWRITE)) {
            __try {
                const unsigned char *p = (const unsigned char *)mbi.BaseAddress;
                if (lk_mem_has(p, mbi.RegionSize, lk_p_gumjs, sizeof lk_p_gumjs)
                    || lk_mem_has(p, mbi.RegionSize, lk_p_frida, sizeof lk_p_frida)) {
                    char key[64];
                    _snprintf(key, sizeof key, "%llx", (unsigned long long)(uintptr_t)mbi.BaseAddress);
                    lk_detect("instrumentation:memory-string", key,
                              "\"region\":%llu,\"size\":%llu",
                              (unsigned long long)(uintptr_t)mbi.BaseAddress,
                              (unsigned long long)mbi.RegionSize);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        if (next <= a) break;
        a = next;
    }
}

/* ---------- bucle principal ---------- */
static void lk_run(void (*tick)(void)) {
    for (;;) {
        if (tick) tick();
        Sleep(lk_interval_ms);
    }
}
