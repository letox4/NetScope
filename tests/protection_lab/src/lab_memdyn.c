/* lab_memdyn.exe — cambios dinámicos de permisos y liberación de regiones.
 * Un hilo "churn" repite cada --churn-ms (20 por defecto):
 *   flip:    PAGE_READWRITE <-> PAGE_READONLY
 *   freeme:  VirtualFree(MEM_RELEASE) y VirtualAlloc en la MISMA dirección
 *   guard:   re-arma PAGE_GUARD sobre la página "guard"
 * "pattern" no se toca nunca (integridad de lecturas). Estado: ciclos y fallos. */
#include "labkit.h"

static volatile LONG cycles = 0, flips = 0, frees = 0, reallocs_ok = 0, reallocs_fail = 0;

static DWORD WINAPI churn(LPVOID unused) {
    (void)unused;
    DWORD ms = (DWORD)lk_optint("--churn-ms", 20);
    LkRegion *fl = lk_find("flip"), *fr = lk_find("freeme"), *gd = lk_find("guard");
    int ro = 0, freed = 0;
    for (;;) {
        DWORD old;
        ro = !ro;
        VirtualProtect((void *)fl->base, LK_PAGE, ro ? PAGE_READONLY : PAGE_READWRITE, &old);
        InterlockedIncrement(&flips);
        if (!freed) {
            if (VirtualFree((void *)fr->base, 0, MEM_RELEASE)) { freed = 1; InterlockedIncrement(&frees); }
        } else {
            void *p = VirtualAlloc((void *)fr->base, fr->size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (p) { freed = 0; memcpy(p, "FREEME-DATA", 11); InterlockedIncrement(&reallocs_ok); }
            else InterlockedIncrement(&reallocs_fail);
        }
        VirtualProtect((void *)gd->base, LK_PAGE, PAGE_READWRITE | PAGE_GUARD, &old);
        InterlockedIncrement(&cycles);
        Sleep(ms);
    }
}

static void status(char *out, size_t n) {
    _snprintf(out, n, "\"cycles\":%ld,\"flips\":%ld,\"frees\":%ld,\"reallocs_ok\":%ld,\"reallocs_fail\":%ld",
              cycles, flips, frees, reallocs_ok, reallocs_fail);
}

int main(int argc, char **argv) {
    lk_init(argc, argv, "memdyn");
    lk_setup_regions();
    lk_user_status = status;
    lk_ready("\"mechanism\":\"dynamic-protection-changes\"");
    CreateThread(NULL, 0, churn, NULL, 0, NULL);
    lk_run(NULL);
    return 0;
}
