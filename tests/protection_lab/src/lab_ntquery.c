/* lab_ntquery.exe — estado de depuración vía NtQueryInformationProcess
 * (ProcessDebugPort=7, ProcessDebugObjectHandle=0x1E, ProcessDebugFlags=0x1F)
 * y lectura directa de PEB.BeingDebugged. */
#include "labkit.h"

static void tick(void) {
    lk_check_ntquery();
    lk_check_peb();
}

int main(int argc, char **argv) {
    lk_init(argc, argv, "ntquery");
    lk_setup_regions();
    lk_ready("\"mechanism\":\"NtQueryInformationProcess+PEB\"");
    lk_run(tick);
    return 0;
}
