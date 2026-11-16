/* lab_instrumentation.exe — busca artefactos de instrumentación (Frida) en su
 * propio proceso: nombres de módulos, nombres de hilos, tuberías con nombre y
 * cadenas en memoria ejecutable privada. SOLO detecta e informa. */
#include "labkit.h"

static int n = 0;

static void tick(void) {
    lk_check_frida_modules();
    lk_check_frida_threads(n == 0 || n % 40 == 0);
    lk_check_frida_pipes();
    if (n % 10 == 0) lk_check_frida_memory();
    n++;
}

int main(int argc, char **argv) {
    lk_init(argc, argv, "instrumentation");
    lk_setup_regions();
    lk_ready("\"mechanism\":\"frida-artifacts\"");
    lk_run(tick);
    return 0;
}
