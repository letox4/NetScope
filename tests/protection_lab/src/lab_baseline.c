/* lab_baseline.exe — control: sin ninguna protección. Solo regiones de prueba,
 * protocolo y (opcionalmente) tráfico de red propio. */
#include "labkit.h"

int main(int argc, char **argv) {
    lk_init(argc, argv, "baseline");
    lk_setup_regions();
    lk_ready("");
    lk_run(NULL);
    return 0;
}
