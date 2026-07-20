package com.nk.integritypro

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Debug
import android.provider.Settings
import android.util.Log
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import com.scottyab.rootbeer.RootBeer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.*
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext

class MainViewModel : ViewModel() {

    // Sourced from gradle.properties via BuildConfig (app/build.gradle.kts) rather than
    // inlined here, so they aren't a single grep-able string in source.
    // NOTE: these are still visible in the compiled APK's resources/bytecode - they are not
    // a substitute for a trust boundary. The authoritative tamper signal is the Play Integrity
    // appIntegrity.appRecognitionVerdict returned by the backend in parseIntegrityReport(),
    // which is verified server-side by Google. EXPECTED_SIGNATURE_HASH below is a fast local
    // pre-check only.
    private val EXPECTED_SIGNATURE_HASH = BuildConfig.EXPECTED_SIGNATURE_HASH
    private val BACKEND_BASE_URL = BuildConfig.BACKEND_BASE_URL
    private val CLOUD_PROJECT_NUMBER = BuildConfig.CLOUD_PROJECT_NUMBER

    // Same SPKI SHA-256 pins declared in res/xml/network_security_config.xml for
    // BACKEND_BASE_URL - duplicated here deliberately so "SSL Pinning Health" verifies the
    // cert independently of the OS-enforced Network Security Config, catching a hooked/
    // replaced global SSLContext that could otherwise bypass NSC pinning entirely.
    private val EXPECTED_BACKEND_PINS_SHA256 = setOf(
        "NnfKqDbhvUeabxD97xg7r9JvWoGY7BJjg8XThNJxVbk=",
        "kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4="
    )

    val logs = mutableStateListOf<LogEntry>()
    var lastIntegrityResult = mutableStateOf("")
    var lastSecurityResults = mutableStateOf<List<CheckResult>>(emptyList())
    var isScanning = mutableStateOf(false)
    var isIntegrityRunning = mutableStateOf(false)

    fun wakeBackend() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val url = URL("$BACKEND_BASE_URL/health")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "GET"
                conn.connectTimeout = 5000
                conn.readTimeout = 5000
                conn.connect()
                conn.disconnect()
            } catch (e: Exception) {
                Log.e("WakeBackend", "Backend warm-up failed", e)
            }
        }
    }

    fun performScan(context: Context) {
        viewModelScope.launch {
            isScanning.value = true
            val results = withContext(Dispatchers.IO) {
                runAllLocalSecurityChecks(context)
            }
            lastSecurityResults.value = results
            results.forEach { result ->
                logs.add(
                    LogEntry(
                        timestamp = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date()),
                        checkName = result.name,
                        status = result.status,
                        message = result.message,
                        isRemote = false
                    )
                )
            }
            isScanning.value = false
        }
    }

    fun runPlayIntegrity(context: Context) {
        viewModelScope.launch {
            isIntegrityRunning.value = true
            val sampleNonce = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(UUID.randomUUID().toString().toByteArray())

            val integrityManager = IntegrityManagerFactory.create(context)
            val tokenRequest = IntegrityTokenRequest.builder()
                .setNonce(sampleNonce)
                .setCloudProjectNumber(CLOUD_PROJECT_NUMBER)
                .build()

            integrityManager.requestIntegrityToken(tokenRequest)
                .addOnSuccessListener { response ->
                    sendTokenToServer(response.token(), sampleNonce)
                }
                .addOnFailureListener { exception ->
                    val msg = "Error: ${exception.message ?: "Unknown"}"
                    lastIntegrityResult.value = "❌ $msg"
                    logs.add(
                        LogEntry(
                            timestamp = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date()),
                            checkName = "Play Integrity",
                            status = CheckStatus.FAIL,
                            message = msg,
                            isRemote = true
                        )
                    )
                    isIntegrityRunning.value = false
                }
        }
    }

    private fun sendTokenToServer(token: String, originalNonce: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val url = URL("$BACKEND_BASE_URL/verify-integrity")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/json; utf-8")
                conn.setRequestProperty("Accept", "application/json")
                conn.doOutput = true
                conn.connectTimeout = 15000
                conn.readTimeout = 15000

                val jsonInputString = "{\"token\": \"$token\"}"
                conn.outputStream.use { os ->
                    val input = jsonInputString.toByteArray(Charsets.UTF_8)
                    os.write(input, 0, input.size)
                }

                if (conn.responseCode == HttpURLConnection.HTTP_OK) {
                    val responseBody = conn.inputStream.bufferedReader().use { it.readText() }
                    withContext(Dispatchers.Main) {
                        handleServerResponse(responseBody, originalNonce)
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        lastIntegrityResult.value = "❌ Server error: HTTP ${conn.responseCode}"
                        isIntegrityRunning.value = false
                    }
                }
                conn.disconnect()
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    lastIntegrityResult.value = "❌ Backend unreachable: ${e.message}"
                    isIntegrityRunning.value = false
                }
            }
        }
    }

    private fun handleServerResponse(responseBody: String, originalNonce: String) {
        val parsed = parseIntegrityReport(responseBody, originalNonce)
        lastIntegrityResult.value = parsed
        val timestamp = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        parsed.split("\n").forEach { line ->
            if (line.isNotBlank()) {
                val status = when {
                    line.contains("✅") -> CheckStatus.PASS
                    line.contains("❌") -> CheckStatus.FAIL
                    line.contains("⚠️") -> CheckStatus.WARNING
                    else -> CheckStatus.PASS
                }
                logs.add(
                    LogEntry(
                        timestamp = timestamp,
                        checkName = "Play Integrity",
                        status = status,
                        message = line.trim(),
                        isRemote = true
                    )
                )
            }
        }
        isIntegrityRunning.value = false
    }

    private fun parseIntegrityReport(jsonString: String, originalNonce: String): String {
        return try {
            val json = JSONObject(jsonString)
            val payload = json.optJSONObject("tokenPayloadExternal") ?: return "❌ Invalid JSON response."

            var report = "☁️ Play Integrity Report\n"
            report += "----------------------------------------\n"

            val requestDetails = payload.optJSONObject("requestDetails")
            val receivedNonce = requestDetails?.optString("nonce", "MISSING")

            report += "Nonce: ${if (receivedNonce == originalNonce) "✅ Match" else "❌ Mismatch"}\n"

            val deviceIntegrity = payload.optJSONObject("deviceIntegrity")
            val deviceVerdicts = deviceIntegrity?.optJSONArray("deviceRecognitionVerdict")
            val deviceVerdictsStr = deviceVerdicts?.toString() ?: "[]"

            report += "Device Integrity Verdicts: $deviceVerdictsStr\n"
            if (deviceVerdictsStr.contains("MEETS_STRONG_INTEGRITY")) {
                report += "  ✅ STRONG INTEGRITY – The device is fully trusted (hardware-backed).\n"
            } else if (deviceVerdictsStr.contains("MEETS_DEVICE_INTEGRITY")) {
                report += "  ✅ DEVICE INTEGRITY – The device is in a good state, but not as strong as strong integrity.\n"
            } else if (deviceVerdictsStr.contains("MEETS_BASIC_INTEGRITY")) {
                report += "  ⚠️ BASIC INTEGRITY – Minimal checks passed; might be a rooted or modified device.\n"
            } else {
                report += "  ❌ UNTRUSTED – The device is compromised or has no valid integrity.\n"
            }

            // New: App Access Risk
            val environmentDetails = payload.optJSONObject("environmentDetails")
            val appAccessRisk = environmentDetails?.optJSONObject("appAccessRiskVerdict")
            if (appAccessRisk != null) {
                val risk = appAccessRisk.optString("appsDetected", "NONE")
                report += "App Access Risk: $risk\n"
                if (risk != "NONE") {
                    report += "  ⚠️ Warning: Potential screen recording or overlay apps detected.\n"
                }
            }

            val appIntegrity = payload.optJSONObject("appIntegrity")
            val appVerdict = appIntegrity?.optString("appRecognitionVerdict", "UNKNOWN")
            report += "App Recognition: $appVerdict\n"
            if (appVerdict == "PLAY_RECOGNIZED") {
                report += "  ✅ The app is officially recognized from Google Play.\n"
            } else if (appVerdict == "UNRECOGNIZED_VERSION") {
                report += "  ⚠️ The app is installed but not recognized – possibly a debug or sideloaded build.\n"
            } else {
                report += "  ❌ App not recognized – may be tampered with.\n"
            }

            val accountDetails = payload.optJSONObject("accountDetails")
            val licenseVerdict = accountDetails?.optString("appLicensingVerdict", "UNKNOWN")
            report += "Licensing: $licenseVerdict\n"
            if (licenseVerdict == "LICENSED") {
                report += "  ✅ The user has a valid license from Google Play.\n"
            } else if (licenseVerdict == "UNEVALUATED") {
                report += "  ⚠️ Licensing could not be evaluated – the app may not be published yet.\n"
            } else {
                report += "  ❌ License invalid – the app is not properly licensed.\n"
            }

            report
        } catch (e: Exception) {
            "❌ Parse error: ${e.message}"
        }
    }

    private fun runAllLocalSecurityChecks(context: Context): List<CheckResult> {
        val results = mutableListOf<CheckResult>()

        // 1. ROOTBEER
        val rootBeer = RootBeer(context)
        val rootPassed = !rootBeer.isRooted
        results.add(CheckResult("Root Detection", if (rootPassed) CheckStatus.PASS else CheckStatus.FAIL,
            if (rootPassed) "No su binaries or root management apps found." else "Found su binaries or root management apps."))

        // 2. EMULATOR
        val isEmulator = (Build.FINGERPRINT.startsWith("generic") || Build.FINGERPRINT.startsWith("unknown")
                || Build.MODEL.contains("google_sdk") || Build.MODEL.contains("Emulator") || Build.MODEL.contains("Android SDK built for x86")
                || Build.BOARD.contains("QC_Reference_Phone") || Build.MANUFACTURER.contains("Genymotion") || Build.HOST.startsWith("Build")
                || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) || "google_sdk" == Build.PRODUCT)
        val emulatorFiles = arrayOf("/dev/socket/qemud", "/system/bin/qemu-props", "/system/lib/libc_malloc_debug_qemu.so")
        val detailedFileLeak = emulatorFiles.any { File(it).exists() }
        val emuPassed = !isEmulator && !detailedFileLeak
        results.add(CheckResult("Emulator", if (emuPassed) CheckStatus.PASS else CheckStatus.FAIL,
            if (emuPassed) "Hardware matches a physical device." else "Emulator or virtual environment detected."))

        // 3. SIGNATURE
        var sigPassed = false
        var sigMsg = ""
        try {
            val currentHash = getAppSignature(context)
            sigPassed = currentHash == EXPECTED_SIGNATURE_HASH
            sigMsg = if (sigPassed) "Certificate matches expected SHA‑256." else "Certificate mismatch – repackaged?"
        } catch (e: Exception) {
            sigMsg = "Could not verify: ${e.message}"
        }
        results.add(CheckResult("App Signature", if (sigPassed) CheckStatus.PASS else CheckStatus.FAIL, sigMsg))

        // 4. ROOT FILES (Magisk & KernelSU)
        val rootPaths = arrayOf(
            "/sbin/.magisk", 
            "/data/adb/magisk", 
            "/data/adb/magisk.db", 
            "/dev/.magisk_unblock", 
            "/data/adb/modules",
            "/system/bin/ksud",
            "/data/adb/ksu",
            "/data/adb/ksu/bin/ksud"
        )
        val rootFilesFound = rootPaths.any { File(it).exists() }
        results.add(CheckResult("Root Files", if (!rootFilesFound) CheckStatus.PASS else CheckStatus.FAIL,
            if (!rootFilesFound) "No suspicious root files (Magisk/KernelSU)." else "Suspicious root files detected."))

        // 5. BUILD TAGS
        val buildTags = Build.TAGS
        val tagsPassed = buildTags?.contains("test-keys") != true
        results.add(CheckResult("Build Tags", if (tagsPassed) CheckStatus.PASS else CheckStatus.FAIL,
            if (tagsPassed) "Build signed with release‑keys." else "Build signed with test‑keys – custom ROM."))

        // 6. SYSTEM MOUNT
        val mountInfo = try { Runtime.getRuntime().exec("mount").inputStream.bufferedReader().readText() } catch (e: Exception) { "" }
        val mountPassed = !mountInfo.contains(" /system ") || !mountInfo.contains(" rw,")
        results.add(CheckResult("System Mount", if (mountPassed) CheckStatus.PASS else CheckStatus.FAIL,
            if (mountPassed) "/system mounted read‑only." else "/system is writable – possible root."))

        // 7. BUSYBOX
        val busyboxPaths = arrayOf("/system/xbin/busybox", "/system/bin/busybox")
        val busyboxFound = busyboxPaths.any { File(it).exists() }
        results.add(CheckResult("BusyBox", if (!busyboxFound) CheckStatus.PASS else CheckStatus.FAIL,
            if (!busyboxFound) "No BusyBox." else "BusyBox found – often installed with root."))

        // 8. BOOTLOADER
        val bootloaderUnlocked = try {
            val prop = ProcessBuilder("getprop", "ro.boot.flash.locked").start()
            val result = prop.inputStream.bufferedReader().readText().trim()
            result == "0"
        } catch (e: Exception) { false }
        results.add(CheckResult("Bootloader", if (!bootloaderUnlocked) CheckStatus.PASS else CheckStatus.FAIL,
            if (!bootloaderUnlocked) "Bootloader locked." else "Bootloader unlocked – device may be rooted."))

        // 9. SELINUX
        val selinuxStatus = try {
            ProcessBuilder("getenforce").start().inputStream.bufferedReader().readText().trim()
        } catch (e: Exception) { "Unknown" }
        val selinuxPassed = !selinuxStatus.equals("Permissive", ignoreCase = true) &&
                !selinuxStatus.equals("Disabled", ignoreCase = true)
        results.add(CheckResult("SELinux", if (selinuxPassed) CheckStatus.PASS else CheckStatus.FAIL,
            if (selinuxPassed) "SELinux enforcing." else "SELinux permissive or disabled."))

        // 10. HOOK FRAMEWORKS (Advanced)
        val hookFound = checkHookFrameworks(context)
        results.add(CheckResult("Hook Frameworks", if (!hookFound) CheckStatus.PASS else CheckStatus.FAIL,
            if (!hookFound) "No hooking frameworks." else "Xposed / LSPosed / Frida detected."))

        // 11. DEBUGGER
        val isDebugged = Debug.isDebuggerConnected() || Debug.waitingForDebugger()
        results.add(CheckResult("Debugger", if (!isDebugged) CheckStatus.PASS else CheckStatus.FAIL,
            if (!isDebugged) "No debugger attached." else "Debugger detected – app under analysis."))

        // 12. TRACER PID
        var tracerPid = 0
        try {
            val statusFile = File("/proc/self/status")
            statusFile.forEachLine { line ->
                if (line.startsWith("TracerPid:")) {
                    tracerPid = line.substringAfter(":").trim().toIntOrNull() ?: 0
                }
            }
        } catch (e: Exception) { tracerPid = -1 }
        results.add(CheckResult("Tracer PID", if (tracerPid == 0) CheckStatus.PASS else CheckStatus.FAIL,
            if (tracerPid == 0) "No tracer process." else "Tracer PID found – possible injection."))

        // 13. VPN DETECTION
        val vpnPassed = try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = cm.activeNetwork
            if (network != null) {
                val caps = cm.getNetworkCapabilities(network)
                caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) != true
            } else {
                true
            }
        } catch (e: Exception) { true }
        results.add(CheckResult("VPN Detection", if (vpnPassed) CheckStatus.PASS else CheckStatus.WARNING,
            if (vpnPassed) "No VPN detected." else "VPN is active – traffic may be intercepted."))

        // 14. DEVELOPER OPTIONS
        val devPassed = try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 0
        } catch (e: Exception) { true }
        results.add(CheckResult("Developer Options", if (devPassed) CheckStatus.PASS else CheckStatus.WARNING,
            if (devPassed) "Developer options are disabled." else "Developer options are enabled – device may be compromised."))

        // 15. USER CA CERTIFICATES
        val certPassed = try {
            val ks = KeyStore.getInstance("AndroidCAStore")
            ks.load(null, null)
            val userAliases = ks.aliases().toList().filter { it.startsWith("user:") }
            userAliases.isEmpty()
        } catch (e: Exception) { true }
        results.add(CheckResult("User CA Certs", if (certPassed) CheckStatus.PASS else CheckStatus.WARNING,
            if (certPassed) "No user‑installed CA certificates found." else "User‑installed CA certificates detected – possible MITM."))

        // 16. USB DEBUGGING
        val usbPassed = try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 0
        } catch (e: Exception) { true }
        results.add(CheckResult("USB Debugging", if (usbPassed) CheckStatus.PASS else CheckStatus.WARNING,
            if (usbPassed) "USB debugging is disabled." else "USB debugging is enabled – device is vulnerable."))

        // 17. ACCESSIBILITY SERVICES
        val accessibilityPassed = try {
            val enabledServices = Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
            enabledServices.isNullOrEmpty()
        } catch (e: Exception) { true }
        results.add(CheckResult("Accessibility Services", if (accessibilityPassed) CheckStatus.PASS else CheckStatus.WARNING,
            if (accessibilityPassed) "No accessibility services enabled." else "Accessibility services are enabled – potential clickjacking."))

        // 18. OVERLAY APPS
        val overlayPassed = checkOverlayPermission(context)
        results.add(CheckResult("Overlay Apps", if (overlayPassed) CheckStatus.PASS else CheckStatus.WARNING,
            if (overlayPassed) "No overlay apps detected." else "Apps with overlay permission found – potential overlay attacks."))

        // 19. UNKNOWN SOURCES
        val unknownSourcesPassed = try {
            Settings.Secure.getInt(context.contentResolver, Settings.Secure.INSTALL_NON_MARKET_APPS, 0) == 0
        } catch (e: Exception) { true }
        results.add(CheckResult("Unknown Sources", if (unknownSourcesPassed) CheckStatus.PASS else CheckStatus.WARNING,
            if (unknownSourcesPassed) "Unknown sources installation is disabled." else "Unknown sources enabled – sideloading risk."))

        // 20. DEBUG BUILD
        val debugBuildPassed = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) == 0
        results.add(CheckResult("Debug Build", if (debugBuildPassed) CheckStatus.PASS else CheckStatus.FAIL,
            if (debugBuildPassed) "App is not debuggable (release build)." else "App is debuggable – increased risk."))

        // 21. ADVANCED EMULATOR (Optimized for Poco X2)
        val advancedEmuPassed = checkAdvancedEmulator()
        results.add(CheckResult("Advanced Emulator", if (advancedEmuPassed) CheckStatus.PASS else CheckStatus.FAIL,
            if (advancedEmuPassed) "No advanced emulator traces found." else "Advanced emulator traces detected (Goldfish/Ranchu)."))

        // 22. SSL PINNING HEALTH - independently re-verifies the backend's certificate pin
        // beyond the OS-level network_security_config.xml, so a hooked/replaced global
        // SSLContext (see TrustManager Tamper Check below) can't silently defeat pinning.
        var sslPinPassed = false
        var sslPinMsg: String
        try {
            // Debug builds target the isolated Render testbed (see network_security_config.xml)
            // so red-team/bypass experiments never touch the real backend; release builds
            // always check the real BACKEND_BASE_URL.
            val targetUrl = if (BuildConfig.DEBUG) BuildConfig.PINNING_TESTBED_URL else BACKEND_BASE_URL
            val conn = URL(targetUrl).openConnection() as HttpsURLConnection
            conn.connectTimeout = 8000
            conn.readTimeout = 8000
            conn.connect()
            val leaf = conn.serverCertificates.firstOrNull() as? X509Certificate
            if (leaf != null) {
                val spkiHash = MessageDigest.getInstance("SHA-256").digest(leaf.publicKey.encoded)
                val pinBase64 = Base64.getEncoder().encodeToString(spkiHash)
                sslPinPassed = pinBase64 in EXPECTED_BACKEND_PINS_SHA256
                sslPinMsg = if (sslPinPassed) "Backend certificate pin verified independently of OS config."
                    else "Certificate pin mismatch - possible MITM or the backend's cert rotated."
            } else {
                sslPinMsg = "No server certificate returned."
            }
            conn.disconnect()
        } catch (e: Exception) {
            sslPinMsg = "Could not verify (likely no network): ${e.message}"
        }
        results.add(CheckResult("SSL Pinning Health", if (sslPinPassed) CheckStatus.PASS else CheckStatus.WARNING, sslPinMsg))

        // 23. TRUSTMANAGER TAMPER CHECK - v2, a confirmed-necessary rewrite of an earlier approach
        // that compared HttpsURLConnection.getDefaultSSLSocketFactory()'s CLASS against a
        // freshly-instantiated reference SSLSocketFactory's class - this is EMPIRICALLY DEFEATED
        // by a global trust-all SSLContext/TrustManager override (a well-known Xposed/Frida SSL
        // pinning bypass pattern): the attacker's factory is built via the same
        // SSLContext.getInstance("TLS") provider machinery as a legitimate one, so its class name
        // is IDENTICAL to a clean reference factory - only the TrustManager instance backing it
        // differs, which the class-comparison approach never inspected. Confirmed via a live
        // LSPosed module test against this app: the old approach silently PASSED while trust-all
        // was active. v2 instead reflectively drills into the actual installed SSLSocketFactory to find the real
        // X509TrustManager instance backing it, and checks whether THAT is a recognized platform
        // (Conscrypt) implementation rather than an attacker-substituted one (typically an anonymous
        // class). This is inherently more fragile across Android versions/OEM ROMs (Conscrypt's
        // internal field layout isn't a stable API) - if reflection can't locate a TrustManager at
        // all, this fails OPEN (PASS) rather than risk a false alarm on a legitimate device where the
        // internal structure just doesn't match what we searched for.
        val trustManagerPassed: Boolean
        val trustManagerMsg: String
        val foundTm = findActiveX509TrustManager()
        if (foundTm == null) {
            trustManagerPassed = true
            trustManagerMsg = "Default TLS trust chain matches the platform default (reflection could not locate a custom TrustManager)."
        } else {
            val tmClassName = foundTm.javaClass.name
            trustManagerPassed = tmClassName.startsWith("com.android.org.conscrypt.")
            trustManagerMsg = if (trustManagerPassed) "Default TLS trust chain matches the platform default."
                else "Non-platform TrustManager active ($tmClassName) - default SSLSocketFactory has likely been globally overridden."
        }
        results.add(CheckResult("TrustManager Tamper Check", if (trustManagerPassed) CheckStatus.PASS else CheckStatus.FAIL, trustManagerMsg))

        // 24. MITM PROXY DETECTION - catches a manually-configured system HTTP proxy (e.g.
        // Burp via Wi-Fi settings). Does NOT catch transparent iptables/DNAT redirection,
        // which doesn't set this system property - a partial signal, not a complete one.
        val proxyHost = System.getProperty("http.proxyHost")
        val proxyPassed = proxyHost.isNullOrBlank()
        results.add(CheckResult("MITM Proxy Detection", if (proxyPassed) CheckStatus.PASS else CheckStatus.WARNING,
            if (proxyPassed) "No system HTTP proxy configured." else "System HTTP proxy detected ($proxyHost) - traffic may be intercepted."))

        // 25. ROOT MANAGER LAUNCH PROBE - resolves (without launching, to avoid disrupting
        // the user's foreground activity) each known root-manager app's launcher intent.
        // Complements the PackageManager-query-based checks above (Hook Frameworks): some
        // hiding modules only spoof getPackageInfo/getInstalledApplications for the calling
        // app's UID but don't intercept intent-resolution queries the same way.
        val rootManagerPassed = checkRootManagerLaunchProbe(context)
        results.add(CheckResult("Root Manager Launch Probe", if (rootManagerPassed) CheckStatus.PASS else CheckStatus.FAIL,
            if (rootManagerPassed) "No root-manager apps resolvable." else "A root-manager app's launcher was resolved - device likely rooted."))

        // 26. HARDWARE ATTESTATION - deeper, harder-to-spoof check than the file/package/mount
        // checks above: generates a hardware-backed key and reads its TEE/StrongBox attestation
        // certificate directly, rather than trusting anything the OS's Java-level APIs report.
        // File-hiding root tools (e.g. SUSFS/Shamiko) that defeat checks 1/4/6/7/10 above have no
        // effect here, since this doesn't look at the filesystem or PackageManager at all.
        results.add(checkHardwareAttestation())

        // 27. NATIVE LIBRARY INJECTION - reads this process's OWN live memory map and thread
        // list for a hooking framework's actual runtime footprint, instead of asking
        // PackageManager whether a hooking app is "installed" (exactly what Shamiko/Zygisk
        // DenyList-style hiding is built to lie about for specific apps).
        results.add(checkNativeLibraryInjection())

        return results
    }

    private val attestationTagRootOfTrust = 704
    private val attestationExtensionOid = "1.3.6.1.4.1.11129.2.1.17"

    // Generates a throwaway hardware-backed (TEE/StrongBox) key with an attestation challenge and
    // reads the resulting certificate's attestation extension for verified-boot state and
    // bootloader lock - the same category of signal Protectt.ai-style commercial RASP SDKs use
    // (their RootOfTrust/VerifyCertificateChain classes read this exact extension). Genuinely
    // harder to spoof than file/package checks: defeating it convincingly requires a forged TEE
    // keybox (e.g. TrickyStore-class tooling), not just hiding files or PackageManager entries.
    private fun checkHardwareAttestation(): CheckResult {
        val keyAlias = "nk_integrity_attestation_probe"
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (keyStore.containsAlias(keyAlias)) keyStore.deleteEntry(keyAlias)

            val challenge = ByteArray(16).also { SecureRandom().nextBytes(it) }
            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            kpg.initialize(
                KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .build()
            )
            kpg.generateKeyPair()

            val chain = keyStore.getCertificateChain(keyAlias)
            try { keyStore.deleteEntry(keyAlias) } catch (_: Exception) { }

            if (chain.isNullOrEmpty()) {
                return CheckResult("Hardware Attestation", CheckStatus.WARNING,
                    "Device returned no certificate chain for a hardware-backed key - cannot verify boot state.")
            }
            val leaf = chain[0] as X509Certificate
            val extBytes = leaf.getExtensionValue(attestationExtensionOid)
                ?: return CheckResult("Hardware Attestation", CheckStatus.WARNING,
                    "No attestation extension present - this key wasn't hardware-attested (software fallback or emulator).")

            // X.509 extension values are always DER OCTET STRING-wrapped; unwrap once to get the
            // real KeyDescription SEQUENCE bytes underneath.
            val keyDescriptionBytes = ASN1OctetString.getInstance(extBytes).octets
            val keyDescription = ASN1Sequence.getInstance(keyDescriptionBytes)
            if (keyDescription.size() < 8) {
                return CheckResult("Hardware Attestation", CheckStatus.WARNING,
                    "Attestation extension has an unexpected structure - cannot parse boot state.")
            }
            val teeEnforced = ASN1Sequence.getInstance(keyDescription.getObjectAt(7))

            var verifiedBootState: Int? = null
            var deviceLocked: Boolean? = null
            for (i in 0 until teeEnforced.size()) {
                val tagged = teeEnforced.getObjectAt(i) as? ASN1TaggedObject ?: continue
                if (tagged.tagNo != attestationTagRootOfTrust) continue
                val rootOfTrust = ASN1Sequence.getInstance(tagged, true)
                if (rootOfTrust.size() >= 3) {
                    deviceLocked = ASN1Boolean.getInstance(rootOfTrust.getObjectAt(1)).isTrue
                    verifiedBootState = ASN1Enumerated.getInstance(rootOfTrust.getObjectAt(2)).value.toInt()
                }
            }

            if (verifiedBootState == null) {
                return CheckResult("Hardware Attestation", CheckStatus.WARNING,
                    "No rootOfTrust field in the attestation - device/OS may not report verified boot state.")
            }
            val stateLabel = when (verifiedBootState) {
                0 -> "Verified"
                1 -> "SelfSigned"
                2 -> "Unverified"
                3 -> "Failed"
                else -> "Unknown($verifiedBootState)"
            }
            val passed = verifiedBootState == 0 && deviceLocked == true
            CheckResult("Hardware Attestation",
                if (passed) CheckStatus.PASS else CheckStatus.FAIL,
                "Verified boot state: $stateLabel, bootloader locked: ${deviceLocked ?: "unknown"}."
                    + if (!passed) " Hardware-backed attestation reports this device is not in a fully trusted boot state." else "")
        } catch (e: Exception) {
            CheckResult("Hardware Attestation", CheckStatus.WARNING, "Could not complete hardware attestation: ${e.message}")
        }
    }

    // Reads this process's OWN live memory map and thread list rather than asking PackageManager
    // whether a hooking app is "installed" - Frida unavoidably injects its own agent/loader into
    // any process it attaches to and spawns a distinctively-named "gum-js-loop" runtime thread,
    // and Xposed/LSPosed/Zygisk-based frameworks load their own native libraries into the
    // process. This sees the actual live footprint directly, which is a fundamentally different
    // (and harder to spoof for a specific app) signal than a static package-existence query.
    private fun checkNativeLibraryInjection(): CheckResult {
        val suspiciousMappedLibs = listOf(
            "frida-agent", "frida-gadget", "libfrida",
            "liblspd", "libriru", "libzygisk", "libsubstrate", "libsubstrator"
        )
        val suspiciousThreadNames = listOf("gum-js-loop", "gmain", "gdbus", "frida-server")

        return try {
            val hitMap = File("/proc/self/maps").readLines()
                .firstOrNull { line -> suspiciousMappedLibs.any { line.contains(it, ignoreCase = true) } }
            if (hitMap != null) {
                return CheckResult("Native Library Injection", CheckStatus.FAIL,
                    "Suspicious library loaded in this process: ${hitMap.substringAfterLast('/')}")
            }

            val hitThread = File("/proc/self/task").listFiles()?.firstNotNullOfOrNull { taskEntry ->
                try {
                    val name = File(taskEntry, "comm").readText().trim()
                    if (suspiciousThreadNames.any { name.equals(it, ignoreCase = true) }) name else null
                } catch (e: Exception) { null }
            }
            if (hitThread != null) {
                return CheckResult("Native Library Injection", CheckStatus.FAIL,
                    "Suspicious thread name found: $hitThread (matches a known Frida/GumJS runtime thread).")
            }

            CheckResult("Native Library Injection", CheckStatus.PASS,
                "No known hooking-framework libraries or threads found in this process.")
        } catch (e: Exception) {
            CheckResult("Native Library Injection", CheckStatus.WARNING, "Could not inspect process memory/threads: ${e.message}")
        }
    }

    // Reflectively searches the currently-installed default SSLSocketFactory's object graph for
    // an X509TrustManager instance, by field TYPE rather than hardcoded field NAMES (Conscrypt's
    // internal field names vary across Android versions/OEM ROMs; searching by type is more
    // resilient than hardcoding e.g. "sslParameters" or "trustManager"). Returns null if none
    // found within a shallow depth (deliberately bounded to avoid walking unrelated object graphs).
    private fun findActiveX509TrustManager(): javax.net.ssl.X509TrustManager? {
        return try {
            findX509TrustManagerIn(HttpsURLConnection.getDefaultSSLSocketFactory(), depth = 0, seen = java.util.Collections.newSetFromMap(java.util.IdentityHashMap()))
        } catch (e: Exception) { null }
    }

    // Known legitimate platform WRAPPER classes that implement X509TrustManager themselves but
    // delegate the actual trust decision to an inner TrustManager - RootTrustManager in
    // particular is what android.security.net.config wraps the real TrustManager in whenever a
    // Network Security Config (network_security_config.xml, which this app itself declares) is
    // active. Treating RootTrustManager as a terminal match was a false positive: it's not the
    // attacker-substituted case this check exists to catch, it's stock Android behavior. Instead
    // of returning at the first X509TrustManager found, drill THROUGH known wrappers to find what
    // they actually delegate to, and only treat a non-wrapper implementation as terminal.
    private val knownTrustManagerWrapperPrefixes = listOf(
        "android.security.net.config."
    )

    private fun findX509TrustManagerIn(obj: Any?, depth: Int, seen: MutableSet<Any>): javax.net.ssl.X509TrustManager? {
        if (obj == null || depth > 6 || !seen.add(obj)) return null
        if (obj is javax.net.ssl.X509TrustManager) {
            val isKnownWrapper = knownTrustManagerWrapperPrefixes.any { obj.javaClass.name.startsWith(it) }
            if (!isKnownWrapper) return obj
            // Known wrapper (e.g. RootTrustManager) - don't trust it blindly by name alone, drill
            // into its own fields below to find and validate the real delegate underneath.
        }
        var cls: Class<*>? = obj.javaClass
        while (cls != null) {
            for (field in cls.declaredFields) {
                try {
                    field.isAccessible = true
                    val value = field.get(obj) ?: continue

                    if (value is javax.net.ssl.X509TrustManager) {
                        // Check the VALUE's actual runtime class here, not the field's static
                        // declared type - a field declared as the X509TrustManager interface
                        // (the common case) would always report "not a wrapper" if checked by
                        // declared type, since the interface name never matches a wrapper prefix
                        // regardless of what concrete class is actually stored in it. This was
                        // the bug in the first version of this fix: it let RootTrustManager
                        // through undetected because the check looked at the wrong type.
                        val valueIsWrapper = knownTrustManagerWrapperPrefixes.any { value.javaClass.name.startsWith(it) }
                        if (!valueIsWrapper) return value
                        val found = findX509TrustManagerIn(value, depth + 1, seen)
                        if (found != null) return found
                        continue
                    }

                    // Recurse into fields whose declared type looks like part of the TLS
                    // provider's own internals (Conscrypt/JSSE/NSC), not arbitrary unrelated
                    // objects.
                    val typeName = field.type.name
                    if (typeName.startsWith("com.android.org.conscrypt.") ||
                        typeName.startsWith("javax.net.ssl.") ||
                        typeName.startsWith("sun.security.ssl.") ||
                        knownTrustManagerWrapperPrefixes.any { typeName.startsWith(it) }) {
                        val found = findX509TrustManagerIn(value, depth + 1, seen)
                        if (found != null) return found
                    }
                } catch (_: Exception) { }
            }
            cls = cls.superclass
        }
        return null
    }

    private val rootManagerPackages = listOf(
        "com.topjohnwu.magisk",
        "me.weishu.kernelsu",
        "com.rifsxd.ksunext",
        "org.lsposed.manager",
        "io.github.lsposed.manager",
        "com.tsng.hidemyapplist",
        "me.bmax.apatch"
    )

    // Layer 1: PackageManager.resolveActivity() - cheap, zero side effects, but confirmed
    // defeatable by a single Xposed hook on
    // ApplicationPackageManager.resolveActivity/queryIntentActivities.
    private fun checkRootManagerLaunchProbe(context: Context): Boolean {
        val layer1Passed = try {
            val pm = context.packageManager
            var found = false
            for (pkg in rootManagerPackages) {
                val intent = android.content.Intent(android.content.Intent.ACTION_MAIN)
                    .addCategory(android.content.Intent.CATEGORY_LAUNCHER)
                    .setPackage(pkg)
                if (pm.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY) != null) {
                    found = true
                    break
                }
            }
            !found
        } catch (e: Exception) { true }

        // If layer 1 already found something, that's a confirmed FAIL - skip layer 2 so we
        // don't risk an unnecessary activity switch on a device that's already flagged.
        if (!layer1Passed) return false

        // Layer 2: a REAL startActivity() attempt - routes through Instrumentation ->
        // ActivityTaskManager, a Binder call into system_server, which is a fundamentally
        // different code path than the local PackageManager.resolveActivity() Java call layer 1
        // uses. A hook that only targets the PM-query layer (exactly what was found defeating
        // layer 1 alone) will not intercept this. Trade-off, deliberately accepted: if a
        // root-manager app genuinely IS installed AND successfully hid from layer 1, this layer
        // will briefly foreground that app (ActivityNotFoundException fires synchronously with
        // no visible transition in the genuine not-installed case, so a clean device never sees
        // any UI change here) - see remediation text shown to the user.
        return checkRootManagerViaStartActivity(context)
    }

    private fun checkRootManagerViaStartActivity(context: Context): Boolean {
        for (pkg in rootManagerPackages) {
            try {
                val intent = android.content.Intent(android.content.Intent.ACTION_MAIN)
                    .addCategory(android.content.Intent.CATEGORY_LAUNCHER)
                    .setPackage(pkg)
                    .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(intent)
                // No exception means the target genuinely exists and was just launched.
                return false
            } catch (e: android.content.ActivityNotFoundException) {
                // Not present - try the next candidate.
            } catch (e: Exception) {
                // Any other failure - inconclusive for this package, don't false-positive.
            }
        }
        return true
    }

    private fun checkHookFrameworks(context: Context): Boolean {
        // Packages
        val hookPackages = listOf(
            "de.robv.android.xposed.installer",
            "org.lsposed.manager",
            "io.github.lsposed.manager",
            "com.topjohnwu.magisk",
            "org.kernel.su"
        )
        val pm = context.packageManager
        for (pkg in hookPackages) {
            try {
                pm.getPackageInfo(pkg, 0)
                return true
            } catch (_: PackageManager.NameNotFoundException) { }
        }

        // Stack Trace Check
        try {
            throw Exception("Checking Stack")
        } catch (e: Exception) {
            for (stackTraceElement in e.stackTrace) {
                if (stackTraceElement.className.contains("de.robv.android.xposed")) return true
            }
        }

        return false
    }

    private fun checkOverlayPermission(context: Context): Boolean {
        return try {
            val apps = context.packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
            val overlayApps = apps.filter { app ->
                context.packageManager.checkPermission(android.Manifest.permission.SYSTEM_ALERT_WINDOW, app.packageName) == PackageManager.PERMISSION_GRANTED
            }
            overlayApps.isEmpty()
        } catch (e: Exception) { true }
    }

    private fun checkAdvancedEmulator(): Boolean {
        return try {
            val props = listOf("ro.kernel.qemu", "qemu.hw.mainkeys")
            var emu = false
            for (prop in props) {
                val value = ProcessBuilder("getprop", prop).start().inputStream.bufferedReader().readText().trim()
                if (value.isNotEmpty() && value != "0") {
                    emu = true
                    break
                }
            }
            // Check for known emulator hardware strings instead of any hardware string
            val hardware = ProcessBuilder("getprop", "ro.hardware").start().inputStream.bufferedReader().readText().trim().lowercase()
            if (hardware.contains("goldfish") || hardware.contains("ranchu") || hardware.contains("vbox86") || hardware.contains("cuttlefish")) {
                emu = true
            }
            !emu
        } catch (e: Exception) { true }
    }

    fun getAppSignature(context: Context): String {
        return try {
            val pm = context.packageManager
            val packageName = context.packageName
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val packageInfo = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                val signingInfo = packageInfo.signingInfo
                val sigs = if (signingInfo?.hasMultipleSigners() == true) signingInfo.apkContentsSigners else signingInfo?.signingCertificateHistory
                if (sigs != null && sigs.isNotEmpty()) getSHA256(sigs[0].toByteArray()) else "N/A"
            } else {
                @Suppress("DEPRECATION", "PackageManagerGetSignatures")
                val packageInfo = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
                val sigs = packageInfo.signatures
                if (sigs != null && sigs.isNotEmpty()) getSHA256(sigs[0].toByteArray()) else "N/A"
            }
        } catch (e: Exception) { "Error: ${e.message}" }
    }

    private fun getSHA256(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(bytes)
        return digest.joinToString("") { "%02X".format(it) }
    }
}
