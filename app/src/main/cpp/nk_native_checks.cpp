// NK Integrity Pro - native-layer tamper/RASP-evasion detection checks.
//
// Added 2026-09-05 after reverse-engineering com.rbl.rootalert's NativeGuard (librasp.so),
// which funnels root/hook detection through checks Java alone can't perform: an ACTIVE
// ptrace() self-test, and inspection of whether commonly-hooked libc symbols have been
// redirected (GOT/symbol-table interposition) or inline-patched (instruction-level trampoline).
// These three checks are this app's own equivalent of that native layer - not a bypass, a
// detector, so it deliberately does the OPPOSITE of what the NK SSL Pinning Bypass Module's
// GROUP 41/42 do: read/verify rather than patch/neutralize.
#include <jni.h>
#include <sys/ptrace.h>
#include <dlfcn.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <cstdint>
#include <string>

// Commonly-hooked libc functions across anti-Frida/anti-tamper literature and confirmed live
// in our own bypass module's own hook lists (open/read/write/access/fopen used by root-file
// checks; ioctl used by socket/port probes; strstr used by string-matching detection logic
// itself, making it a favorite Frida Interceptor target to blind a check from the inside).
static const char *const kWatchedSymbols[] = {
        "open", "read", "write", "ioctl", "fopen", "access", "strstr"
};
static const size_t kWatchedSymbolCount = sizeof(kWatchedSymbols) / sizeof(kWatchedSymbols[0]);

// Parses /proc/self/maps for the FIRST executable ("r-xp") mapping whose path contains
// "libc.so", returning [start, end). Multiple libc.so mappings normally exist (text vs
// rodata segments at different perms) - we only need the executable one, since that's the
// legitimate range any of kWatchedSymbols' real code can live in.
static bool getLibcExecRange(uintptr_t *start, uintptr_t *end) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libc.so") && strstr(line, "r-xp")) {
            unsigned long a = 0, b = 0;
            if (sscanf(line, "%lx-%lx", &a, &b) == 2) {
                *start = (uintptr_t) a;
                *end = (uintptr_t) b;
                found = true;
                break;
            }
        }
    }
    fclose(f);
    return found;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_nk_integritypro_NativeChecks_nativePtraceSelfTest(JNIEnv *, jobject) {
    // A process can only have ONE tracer at a time. If a debugger/Frida is ALREADY attached,
    // this call fails with EPERM - the standard, single-syscall Linux/Android anti-debug
    // technique (OWASP MASTG documents this exact pattern). Deliberately does NOT attempt to
    // detach or otherwise alter tracer state afterward - the check itself is the whole point,
    // and this app's own parent (zygote/app_process) becoming the tracer on a successful call
    // is a harmless, well-known side effect of the technique, not something to undo.
    errno = 0;
    long result = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
    if (result == 0) return 0;           // clean - no tracer was attached
    if (errno == EPERM) return 1;        // already traced (debugger/Frida present)
    return -1;                            // unexpected error - inconclusive, not a verdict
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_nk_integritypro_NativeChecks_nativeCheckGotSymbolHooks(JNIEnv *env, jobject) {
    uintptr_t libcStart = 0, libcEnd = 0;
    if (!getLibcExecRange(&libcStart, &libcEnd)) {
        return nullptr; // couldn't establish a baseline range - fail open, don't guess
    }
    for (size_t i = 0; i < kWatchedSymbolCount; i++) {
        void *addr = dlsym(RTLD_DEFAULT, kWatchedSymbols[i]);
        if (addr == nullptr) continue; // symbol not resolvable here - not a finding either way
        auto a = (uintptr_t) addr;
        if (a < libcStart || a >= libcEnd) {
            char msg[192];
            snprintf(msg, sizeof(msg),
                     "Symbol '%s' resolves to 0x%lx, outside libc.so's own mapped range "
                     "[0x%lx-0x%lx) - possible GOT/symbol-table redirection.",
                     kWatchedSymbols[i], (unsigned long) a, (unsigned long) libcStart,
                     (unsigned long) libcEnd);
            return env->NewStringUTF(msg);
        }
    }
    return nullptr; // all watched symbols resolve inside libc.so - clean
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_nk_integritypro_NativeChecks_nativeCheckInlineHooks(JNIEnv *env, jobject) {
#if defined(__aarch64__)
    for (size_t i = 0; i < kWatchedSymbolCount; i++) {
        void *addr = dlsym(RTLD_DEFAULT, kWatchedSymbols[i]);
        if (addr == nullptr) continue;
        // Reading 4 bytes of already-mapped, already-executable code in our own address space
        // is always safe - no special permission needed, this is not writing.
        auto instr = *reinterpret_cast<const uint32_t *>(addr);
        // ARM64 unconditional branch encodings: B is 0b000101 in bits[31:26], BL is 0b100101.
        // A legitimate libc function prologue essentially never starts with a direct branch to
        // an arbitrary 26-bit-signed offset (real prologues push registers / adjust SP first) -
        // this is exactly the instruction Frida's default Interceptor.attach() trampoline writes
        // at a hooked function's entry point. Heuristic, not exhaustive: a hook using the
        // alternate "LDR X17,[PC+8]; BR X17; <8-byte addr>" gadget form isn't caught by this
        // single-opcode check - one more layer of defense-in-depth, not a guaranteed catch, same
        // honesty standard as this app's other native-level checks.
        uint32_t top6 = instr >> 26;
        if (top6 == 0b000101 || top6 == 0b100101) {
            char msg[192];
            snprintf(msg, sizeof(msg),
                     "Function '%s' at %p begins with an unconditional branch instruction "
                     "(0x%08x) instead of a normal prologue - possible inline hook trampoline.",
                     kWatchedSymbols[i], addr, instr);
            return env->NewStringUTF(msg);
        }
    }
    return nullptr;
#else
    (void) env;
    return nullptr; // heuristic is ARM64-instruction-encoding-specific; no-op on other ABIs
#endif
}
