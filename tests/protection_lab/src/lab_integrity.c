/* lab_integrity.exe — detección de modificaciones de integridad:
 *  - prólogos de funciones (ws2_32/kernel32/ntdll...) frente a una línea base
 *    tomada al arrancar (detecta hooks inline, p. ej. Interceptor de Frida);
 *  - hash de las secciones ejecutables de su propia imagen. */
#include "labkit.h"

static void tick(void) {
    lk_check_hooks();
    lk_check_text();
}

int main(int argc, char **argv) {
    lk_init(argc, argv, "integrity");
    lk_setup_regions();
    lk_hooks_baseline();
    lk_text_base_hash = lk_text_hash();
    lk_ready("\"mechanism\":\"inline-hook+code-hash\"");
    lk_run(tick);
    return 0;
}
