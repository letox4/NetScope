/* lab_terminator.exe — terminación deliberada del proceso.
 *   --detectors=none|debug|integrity|instrumentation|exec|all  (lista separada por comas)
 *       debug           IsDebuggerPresent + CheckRemoteDebuggerPresent + NtQueryInformationProcess + PEB
 *       integrity       prólogos de API (hooks inline) + hash de código
 *       instrumentation módulos/hilos/tuberías/cadenas de Frida
 *       exec            cambios en memoria ejecutable
 *   --on-detect=exit|terminate|crash|failfast   cómo termina al detectar (por defecto exit)
 *   --die-after-ms=N --die-mode=exit|terminate|crash|failfast
 *       muerte incondicional pasados N ms (control: terminación SIN detección). */
#include "labkit.h"

static int d_debug, d_integrity, d_instr, d_exec;
static int n = 0;

static void tick(void) {
    if (d_debug) { lk_check_isdebuggerpresent(); lk_check_remote(); lk_check_ntquery(); lk_check_peb(); }
    if (d_integrity) { lk_check_hooks(); lk_check_text(); }
    if (d_instr) {
        lk_check_frida_modules(); lk_check_frida_threads(0); lk_check_frida_pipes();
        if (n % 10 == 0) lk_check_frida_memory();
    }
    if (d_exec) lk_check_exec();
    n++;
}

static DWORD WINAPI die_thread(LPVOID p) {
    int action = (int)(intptr_t)p;
    Sleep((DWORD)lk_optint("--die-after-ms", 0));
    lk_die(action, "timer");
    return 0;
}

int main(int argc, char **argv) {
    lk_init(argc, argv, "terminator");
    if (lk_on_detect == LK_REPORT) lk_on_detect = LK_EXIT;
    lk_setup_regions();
    const char *det = lk_opt("--detectors");
    if (!det) det = "none";
    int all = !strcmp(det, "all");
    d_debug = all || strstr(det, "debug") != NULL;
    d_integrity = all || strstr(det, "integrity") != NULL;
    d_instr = all || strstr(det, "instrumentation") != NULL;
    d_exec = all || strstr(det, "exec") != NULL;
    if (d_integrity) { lk_hooks_baseline(); lk_text_base_hash = lk_text_hash(); }
    if (d_exec) { lk_exec_baseline(); if (!d_integrity) lk_text_base_hash = lk_text_hash(); }
    lk_ready("\"mechanism\":\"deliberate-termination\"");
    if (lk_opt("--die-after-ms")) {
        const char *m = lk_opt("--die-mode");
        int a = LK_EXIT;
        if (m && !strcmp(m, "terminate")) a = LK_TERMINATE;
        else if (m && !strcmp(m, "crash")) a = LK_CRASH;
        else if (m && !strcmp(m, "failfast")) a = LK_FAILFAST;
        CreateThread(NULL, 0, die_thread, (LPVOID)(intptr_t)a, 0, NULL);
    }
    lk_run(tick);
    return 0;
}
