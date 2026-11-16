/* lab_isdebugger.exe — consulta IsDebuggerPresent() de forma periódica.
 * Configuración: ninguna obligatoria. --on-detect=exit para terminar al detectar. */
#include "labkit.h"

static void tick(void) { lk_check_isdebuggerpresent(); }

int main(int argc, char **argv) {
    lk_init(argc, argv, "isdebugger");
    lk_setup_regions();
    lk_ready("\"mechanism\":\"IsDebuggerPresent\"");
    lk_run(tick);
    return 0;
}
