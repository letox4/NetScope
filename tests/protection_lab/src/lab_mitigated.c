/* lab_mitigated.exe — se aplica a sí mismo mitigaciones de Windows con la API
 * OFICIAL SetProcessMitigationPolicy y verifica con GetProcessMitigationPolicy.
 *   --policy=dyncode,signature,imageload,extpoint,handle,cfg,childproc   (o "all")
 * Tras el arranque informa: eventos "policy" (resultado de cada una), "mitigations"
 * (estado real) e "ifeo" (valor MitigationOptions en Image File Execution Options,
 * donde Windows guarda la configuración persistente de Exploit Protection, EAF
 * incluido). Las mitigaciones aplicadas EN EL ARRANQUE (CreateProcess) las
 * lanza run_matrix.py con PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY. */
#include "labkit.h"

static int apply(const char *name, PROCESS_MITIGATION_POLICY p, void *s, size_t n) {
    BOOL ok = SetProcessMitigationPolicy(p, s, n);
    lk_emit("policy", "\"name\":\"%s\",\"ok\":%d,\"error\":%lu", name, ok ? 1 : 0, ok ? 0 : GetLastError());
    return ok;
}

static void apply_policies(const char *list) {
    int all = !strcmp(list, "all");
    if (all || strstr(list, "dyncode")) {
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY s; memset(&s, 0, sizeof s);
        s.ProhibitDynamicCode = 1;
        apply("dyncode", ProcessDynamicCodePolicy, &s, sizeof s);
    }
    if (all || strstr(list, "signature")) {
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY s; memset(&s, 0, sizeof s);
        s.MicrosoftSignedOnly = 1;
        apply("signature", ProcessSignaturePolicy, &s, sizeof s);
    }
    if (all || strstr(list, "imageload")) {
        PROCESS_MITIGATION_IMAGE_LOAD_POLICY s; memset(&s, 0, sizeof s);
        s.NoRemoteImages = 1; s.NoLowMandatoryLabelImages = 1; s.PreferSystem32Images = 1;
        apply("imageload", ProcessImageLoadPolicy, &s, sizeof s);
    }
    if (all || strstr(list, "extpoint")) {
        PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY s; memset(&s, 0, sizeof s);
        s.DisableExtensionPoints = 1;
        apply("extpoint", ProcessExtensionPointDisablePolicy, &s, sizeof s);
    }
    if (all || strstr(list, "handle")) {
        PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY s; memset(&s, 0, sizeof s);
        s.RaiseExceptionOnInvalidHandleReference = 1; s.HandleExceptionsPermanentlyEnabled = 1;
        apply("handle", ProcessStrictHandleCheckPolicy, &s, sizeof s);
    }
    if (all || strstr(list, "cfg")) {
        PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY s; memset(&s, 0, sizeof s);
        s.EnableControlFlowGuard = 1;
        apply("cfg", ProcessControlFlowGuardPolicy, &s, sizeof s);
    }
    if (all || strstr(list, "childproc")) {
        PROCESS_MITIGATION_CHILD_PROCESS_POLICY s; memset(&s, 0, sizeof s);
        s.NoChildProcessCreation = 1;
        apply("childproc", ProcessChildProcessPolicy, &s, sizeof s);
    }
}

static void report_state(void) {
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dc; memset(&dc, 0, sizeof dc);
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sg; memset(&sg, 0, sizeof sg);
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY il; memset(&il, 0, sizeof il);
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cf; memset(&cf, 0, sizeof cf);
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ep; memset(&ep, 0, sizeof ep);
    PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY ss; memset(&ss, 0, sizeof ss);
    HANDLE h = GetCurrentProcess();
    GetProcessMitigationPolicy(h, ProcessDynamicCodePolicy, &dc, sizeof dc);
    GetProcessMitigationPolicy(h, ProcessSignaturePolicy, &sg, sizeof sg);
    GetProcessMitigationPolicy(h, ProcessImageLoadPolicy, &il, sizeof il);
    GetProcessMitigationPolicy(h, ProcessControlFlowGuardPolicy, &cf, sizeof cf);
    GetProcessMitigationPolicy(h, ProcessExtensionPointDisablePolicy, &ep, sizeof ep);
    BOOL ssok = GetProcessMitigationPolicy(h, ProcessUserShadowStackPolicy, &ss, sizeof ss);
    lk_emit("mitigations",
            "\"dyncode\":%d,\"signature_ms_only\":%d,\"image_no_remote\":%d,\"image_system32\":%d,"
            "\"cfg\":%d,\"cfg_strict\":%d,\"extpoint\":%d,\"user_shadow_stack\":%d",
            (int)dc.ProhibitDynamicCode, (int)sg.MicrosoftSignedOnly, (int)il.NoRemoteImages,
            (int)il.PreferSystem32Images, (int)cf.EnableControlFlowGuard, (int)cf.StrictMode,
            (int)ep.DisableExtensionPoints, ssok ? (int)ss.EnableUserShadowStack : -1);
}

static void report_ifeo(void) {
    char exe[MAX_PATH], key[512], hex[256] = "";
    GetModuleFileNameA(NULL, exe, MAX_PATH);
    const char *base = strrchr(exe, '\\');
    base = base ? base + 1 : exe;
    _snprintf(key, sizeof key,
              "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s", base);
    HKEY k;
    int exists = RegOpenKeyExA(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &k) == ERROR_SUCCESS;
    if (exists) {
        unsigned char buf[64];
        DWORD n = sizeof buf, type = 0;
        if (RegQueryValueExA(k, "MitigationOptions", NULL, &type, buf, &n) == ERROR_SUCCESS)
            lk_hex(hex, buf, n < 64 ? n : 64);
        RegCloseKey(k);
    }
    lk_emit("ifeo", "\"image\":\"%s\",\"key_exists\":%d,\"mitigation_options\":\"%s\"", base, exists, hex);
}

int main(int argc, char **argv) {
    lk_init(argc, argv, "mitigated");
    lk_setup_regions();
    const char *pol = lk_opt("--policy");
    lk_ready("\"mechanism\":\"SetProcessMitigationPolicy\"");
    if (pol && *pol) apply_policies(pol);
    report_state();
    report_ifeo();
    lk_run(NULL);
    return 0;
}
