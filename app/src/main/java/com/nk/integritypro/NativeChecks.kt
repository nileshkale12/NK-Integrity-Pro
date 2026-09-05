package com.nk.integritypro

// JNI bridge to nk_native_checks.cpp - the 3 detection checks that genuinely need native code
// (an active ptrace() self-test, and GOT/inline-hook inspection of libc symbols) rather than
// pure Kotlin/Java APIs. See MainViewModel's checks #34-36 for how these are interpreted.
object NativeChecks {
    private var loaded = false

    init {
        loaded = try {
            System.loadLibrary("nk_native_checks")
            true
        } catch (_: Throwable) {
            false
        }
    }

    val isLoaded: Boolean get() = loaded

    // 0 = clean (no tracer attached), 1 = already traced, -1 = inconclusive/error
    external fun nativePtraceSelfTest(): Int

    // null = clean, non-null = human-readable description of the offending symbol/address
    external fun nativeCheckGotSymbolHooks(): String?

    external fun nativeCheckInlineHooks(): String?
}
