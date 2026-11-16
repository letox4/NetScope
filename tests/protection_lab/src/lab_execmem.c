/* lab_execmem.exe — detección de cambios en memoria ejecutable:
 * regiones propias RX y RWX + secciones ejecutables de la imagen.
 * Comandos: selfmod rwx | selfmod rx  (se modifica a sí mismo para probar la detección). */
#include "labkit.h"

static void cmd(const char *line) {
    if (!strncmp(line, "selfmod ", 8)) {
        LkRegion *r = lk_find(strcmp(line + 8, "rx") ? "rwx" : "rx");
        DWORD old;
        VirtualProtect((void *)r->base, LK_PAGE, PAGE_EXECUTE_READWRITE, &old);
        ((unsigned char *)r->base)[1] ^= 0xFF;
        if (!strcmp(r->name, "rx")) VirtualProtect((void *)r->base, LK_PAGE, PAGE_EXECUTE_READ, &old);
        lk_emit("ack", "\"cmd\":\"selfmod\",\"region\":\"%s\"", r->name);
    }
}

static void tick(void) {
    lk_check_exec();
    lk_check_text();
}

int main(int argc, char **argv) {
    lk_init(argc, argv, "execmem");
    lk_setup_regions();
    lk_exec_baseline();
    lk_text_base_hash = lk_text_hash();
    lk_user_cmd = cmd;
    lk_ready("\"mechanism\":\"executable-memory-hash\"");
    lk_run(tick);
    return 0;
}
