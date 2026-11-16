/* lab_remotedbg.exe — CheckRemoteDebuggerPresent(GetCurrentProcess()) periódico. */
#include "labkit.h"

static void tick(void) { lk_check_remote(); }

int main(int argc, char **argv) {
    lk_init(argc, argv, "remotedbg");
    lk_setup_regions();
    lk_ready("\"mechanism\":\"CheckRemoteDebuggerPresent\"");
    lk_run(tick);
    return 0;
}
