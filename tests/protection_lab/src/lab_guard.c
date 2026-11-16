/* lab_guard.exe — PAGE_GUARD real + vigilancia por VEH.
 *
 * Páginas con PAGE_GUARD: "guard" y la 2.ª página de "edge". Un manejador de
 * excepciones vectorizado (VEH) registra cada STATUS_GUARD_PAGE_VIOLATION:
 * dirección tocada, tipo de acceso (0 lectura, 1 escritura, 8 ejecución), RIP y
 * módulo que accedió. Opciones:
 *   --rearm          rearmar la guarda tras cada acceso (single-step), como hace EAF
 *   --eaf-emulate    añade PAGE_GUARD a las páginas de la tabla de exportación de
 *                    kernel32/kernelbase/ntdll de ESTE proceso y trata como violación
 *                    el acceso desde un módulo que no sea de sistema ni el .exe
 *                    (emulación del mecanismo de EAF; el EAF real se configura con
 *                    scripts/eaf_enable.ps1 y requiere elevación)
 *   --oneshot        no rearmar (la guarda se consume en el primer acceso, sin single-step)
 *   --eaf-lazy       no armar las páginas EAT al arrancar; se arman con el comando "rearm"
 * Comandos: touch guard | touch edge | rearm
 */
#include "labkit.h"

#define MAXPG 64
typedef struct { unsigned long long fault, rip; unsigned long tid; int access, page; } Hit;

static uintptr_t pg[MAXPG];
static DWORD pgprot[MAXPG];
static char pgname[MAXPG][40];
static int pgeaf[MAXPG];
static volatile LONG pghits[MAXPG];
static int npg = 0;
static Hit ring[512];
static volatile LONG ring_w = 0;
static LONG ring_r = 0;
static int rearm_all = 0, eaf = 0, oneshot = 0;
static __declspec(thread) uintptr_t pending_rearm = 0;

static int add_pg(const char *name, uintptr_t addr, DWORD prot, int is_eaf) {
    if (npg >= MAXPG) return -1;
    pg[npg] = addr & ~(uintptr_t)(LK_PAGE - 1);
    pgprot[npg] = prot;
    pgeaf[npg] = is_eaf;
    _snprintf(pgname[npg], sizeof pgname[npg], "%s", name);
    return npg++;
}

static int find_pg(uintptr_t a) {
    a &= ~(uintptr_t)(LK_PAGE - 1);
    for (int i = 0; i < npg; i++) if (pg[i] == a) return i;
    return -1;
}

static LONG CALLBACK veh(PEXCEPTION_POINTERS ep) {
    PEXCEPTION_RECORD er = ep->ExceptionRecord;
    if (er->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION && er->NumberParameters >= 2) {
        int i = find_pg((uintptr_t)er->ExceptionInformation[1]);
        if (i >= 0) {
            InterlockedIncrement(&pghits[i]);
            LONG w = InterlockedIncrement(&ring_w) - 1;
            Hit *h = &ring[w % 512];
            h->fault = (unsigned long long)er->ExceptionInformation[1];
            h->rip = (unsigned long long)(uintptr_t)er->ExceptionAddress;
            h->tid = GetCurrentThreadId();
            h->access = (int)er->ExceptionInformation[0];
            h->page = i;
            if ((rearm_all || pgeaf[i]) && !oneshot) {
                pending_rearm = pg[i];
                ep->ContextRecord->EFlags |= 0x100;      /* TF: un paso y volvemos a armar */
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    } else if (er->ExceptionCode == EXCEPTION_SINGLE_STEP && pending_rearm) {
        DWORD old;
        int i = find_pg(pending_rearm);
        pending_rearm = 0;
        if (i >= 0) VirtualProtect((void *)pg[i], LK_PAGE, pgprot[i] | PAGE_GUARD, &old);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void arm_eaf_module(const char *mod) {
    HMODULE m = GetModuleHandleA(mod);
    if (!m) return;
    unsigned char *base = (unsigned char *)m;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    IMAGE_DATA_DIRECTORY d = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    uintptr_t a = ((uintptr_t)base + d.VirtualAddress) & ~(uintptr_t)(LK_PAGE - 1);
    uintptr_t end = (uintptr_t)base + d.VirtualAddress + d.Size;
    for (; a < end; a += LK_PAGE) {
        MEMORY_BASIC_INFORMATION mbi;
        char nm[40];
        _snprintf(nm, sizeof nm, "eaf:%s", mod);
        VirtualQuery((void *)a, &mbi, sizeof mbi);
        DWORD prot = mbi.Protect & 0xFF;
        if (add_pg(nm, a, prot, 1) < 0) return;
    }
}

static void arm_all(void) {
    for (int i = 0; i < npg; i++) {
        DWORD old;
        VirtualProtect((void *)pg[i], LK_PAGE, pgprot[i] | PAGE_GUARD, &old);
    }
}

static void cmd(const char *line) {
    if (!strncmp(line, "touch ", 6)) {
        LkRegion *r = lk_find(strcmp(line + 6, "edge") ? "guard" : "edge");
        volatile unsigned char *p = (volatile unsigned char *)(r->base + (r->size - LK_PAGE));
        if (!strcmp(r->name, "edge")) p = (volatile unsigned char *)(r->base + LK_PAGE);
        unsigned char v = *p;
        lk_emit("ack", "\"cmd\":\"touch\",\"region\":\"%s\",\"byte\":%d", r->name, v);
    } else if (!strcmp(line, "rearm")) {
        arm_all();
        lk_emit("ack", "\"cmd\":\"rearm\",\"pages\":%d", npg);
    }
}

static void status(char *out, size_t n) {
    size_t o = (size_t)_snprintf(out, n, "\"eaf_emulate\":%d,\"guard_pages\":%d,\"guard_hits\":{", eaf, npg);
    int first = 1;
    for (int i = 0; i < npg; i++)
        if (pghits[i] && o + 80 < n) {
            o += (size_t)_snprintf(out + o, n - o, "%s\"%s.%d\":%ld", first ? "" : ",", pgname[i], i, pghits[i]);
            first = 0;
        }
    _snprintf(out + o, n - o, "}");
}

static void tick(void) {
    InterlockedIncrement(&lk_checks);
    while (ring_r < ring_w) {
        Hit h = ring[ring_r % 512];
        ring_r++;
        char mod[MAX_PATH] = "(anonymous)";
        HMODULE hm = NULL;
        int is_exe = 0, is_sys = 0;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)(uintptr_t)h.rip, &hm)) {
            GetModuleFileNameA(hm, mod, MAX_PATH);
            is_exe = hm == GetModuleHandleA(NULL);
            is_sys = lk_is_system_path(mod);
        }
        char esc[2 * MAX_PATH];
        lk_esc(esc, sizeof esc, mod);
        lk_emit("guard-hit", "\"page\":\"%s\",\"access\":%d,\"fault\":%llu,\"rip\":%llu,\"module\":\"%s\","
                             "\"tid\":%lu,\"system_module\":%d,\"self\":%d",
                pgname[h.page], h.access, h.fault, h.rip, esc, h.tid, is_sys, is_exe);
        if (eaf && pgeaf[h.page] && !is_sys && !is_exe) {
            char key[MAX_PATH + 32];
            _snprintf(key, sizeof key, "%s@%llx", esc, h.rip & ~0xFFFULL);
            lk_detect("eaf-style:export-table-access", key,
                      "\"page\":\"%s\",\"module\":\"%s\",\"rip\":%llu,\"tid\":%lu",
                      pgname[h.page], esc, h.rip, h.tid);
        }
    }
}

int main(int argc, char **argv) {
    lk_init(argc, argv, "guard");
    lk_setup_regions();
    rearm_all = lk_opt("--rearm") != NULL;
    eaf = lk_opt("--eaf-emulate") != NULL;
    oneshot = lk_opt("--oneshot") != NULL;
    AddVectoredExceptionHandler(1, veh);
    add_pg("guard", lk_find("guard")->base, PAGE_READWRITE, 0);
    add_pg("edge+1", lk_find("edge")->base + LK_PAGE, PAGE_READWRITE, 0);
    if (eaf) {
        arm_eaf_module("kernel32.dll");
        arm_eaf_module("kernelbase.dll");
        arm_eaf_module("ntdll.dll");
        if (!lk_opt("--eaf-lazy")) arm_all();   /* --eaf-lazy: armar solo con el comando "rearm" */
    }
    lk_user_cmd = cmd;
    lk_user_status = status;
    lk_ready(eaf ? "\"mechanism\":\"PAGE_GUARD+VEH+eaf-emulate\"" : "\"mechanism\":\"PAGE_GUARD+VEH\"");
    lk_run(tick);
    return 0;
}
