package com.nk.integritypro

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.google.android.gms.ads.identifier.AdvertisingIdClient
import com.nk.integritypro.ui.theme.NkIntegrityTheme
import com.nk.integritypro.ui.theme.NkTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.*

// ============================================================
// MODERN COLORS
// Reactive to NkTheme.isDark so the whole screen re-themes on toggle,
// since these are read directly by composables rather than via MaterialTheme.colorScheme.
// ============================================================
val GlassBg: Color get() = NkTheme.colors.background
val GlassSurface: Color get() = NkTheme.colors.surface
val GlassCardBg: Color get() = NkTheme.colors.cardBackground
val GlassBorder: Color get() = NkTheme.colors.cardBorder
val AccentPrimary: Color get() = NkTheme.colors.accentPrimary
val AccentSecondary: Color get() = NkTheme.colors.accentSecondary
val Success: Color get() = NkTheme.colors.success
val Warning: Color get() = NkTheme.colors.warning
val Danger: Color get() = NkTheme.colors.danger
val TextPrimary: Color get() = NkTheme.colors.textPrimary
val TextSecondary: Color get() = NkTheme.colors.textSecondary

// The four screen-header banners always use a dark gradient background (see GlassCard-adjacent
// header Boxes below), independent of light/dark theme, so their text/icon color stays fixed
// rather than following TextPrimary/TextSecondary.
val HeaderTextPrimary = Color.White
val HeaderTextSecondary = Color(0xFFB0BEC5)

val MonospaceBodyStyle = TextStyle(
    fontFamily = FontFamily.Monospace,
    fontSize = 13.sp
)

// ============================================================
// DATA CLASSES
// ============================================================
enum class Screen { SECURITY, INTEGRITY, DEVICE_INFO, CHECKS }

data class DeviceInfoItem(val category: String, val key: String, val value: String)

data class CheckResult(
    val name: String,
    val status: CheckStatus,
    val message: String
)

enum class CheckStatus { PASS, FAIL, WARNING }

// ============================================================
// SEVERITY / CHECK MODE
// CheckMode is a user-selectable display filter (Low/Medium/High), not an execution
// filter - every check always runs every scan (all are cheap local checks), the mode
// only controls what's shown/counted so switching mode never requires a rescan.
// ============================================================
enum class CheckSeverity { LOW, MEDIUM, HIGH }

enum class CheckMode(val label: String) {
    LOW("Low"), MEDIUM("Medium"), HIGH("High");

    fun includes(severity: CheckSeverity): Boolean = when (this) {
        LOW -> severity == CheckSeverity.LOW
        MEDIUM -> severity == CheckSeverity.LOW || severity == CheckSeverity.MEDIUM
        HIGH -> true
    }
}

val checkSeverity = mapOf(
    "Root Detection" to CheckSeverity.HIGH,
    "Emulator" to CheckSeverity.MEDIUM,
    "App Signature" to CheckSeverity.HIGH,
    "Root Files" to CheckSeverity.HIGH,
    "Build Tags" to CheckSeverity.MEDIUM,
    "System Mount" to CheckSeverity.MEDIUM,
    "BusyBox" to CheckSeverity.MEDIUM,
    "Bootloader" to CheckSeverity.MEDIUM,
    "SELinux" to CheckSeverity.MEDIUM,
    "Hook Frameworks" to CheckSeverity.HIGH,
    "Debugger" to CheckSeverity.HIGH,
    "Tracer PID" to CheckSeverity.HIGH,
    "VPN Detection" to CheckSeverity.MEDIUM,
    "Developer Options" to CheckSeverity.LOW,
    "User CA Certs" to CheckSeverity.MEDIUM,
    "USB Debugging" to CheckSeverity.LOW,
    "Accessibility Services" to CheckSeverity.LOW,
    "Overlay Apps" to CheckSeverity.MEDIUM,
    "Unknown Sources" to CheckSeverity.LOW,
    "Debug Build" to CheckSeverity.HIGH,
    "Advanced Emulator" to CheckSeverity.HIGH,
    "SSL Pinning Health" to CheckSeverity.HIGH,
    "TrustManager Tamper Check" to CheckSeverity.HIGH,
    "MITM Proxy Detection" to CheckSeverity.MEDIUM,
    "Root Manager Launch Probe" to CheckSeverity.HIGH,
    "Hardware Attestation" to CheckSeverity.HIGH,
    "Native Library Injection" to CheckSeverity.HIGH,
    "Insecure Build Properties" to CheckSeverity.HIGH,
    "Installer Source" to CheckSeverity.MEDIUM,
    "Frida Server Port Scan" to CheckSeverity.HIGH,
    "Magisk Socket Leak" to CheckSeverity.HIGH,
    "Mount Namespace Leak" to CheckSeverity.HIGH,
    "Attestation Key Revocation" to CheckSeverity.HIGH
)

// Global, reactive current check-mode selection - mirrors the NkTheme.isDark pattern
// (ui/theme/Theme.kt) so every screen re-renders on change with no rescan needed.
object NkCheckMode {
    var mode by mutableStateOf(CheckMode.HIGH)
}

data class LogEntry(
    val timestamp: String,
    val checkName: String,
    val status: CheckStatus,
    val message: String,
    val isRemote: Boolean = false
)

val checkDescriptions = mapOf(
    "Root Detection" to "Checks for superuser binaries and root management apps.",
    "Emulator" to "Detects if the app is running inside an emulator or virtual environment.",
    "App Signature" to "Verifies the app's signing certificate against the expected SHA‑256.",
    "Root Files" to "Scans for Magisk, KernelSU, and other superuser management files.",
    "Build Tags" to "Checks if the ROM is signed with release‑keys (safe) or test‑keys (custom).",
    "System Mount" to "Determines if the system partition is writable (potential root).",
    "BusyBox" to "Looks for BusyBox binaries often installed with root.",
    "Bootloader" to "Checks if the bootloader is unlocked (may indicate custom firmware).",
    "SELinux" to "Verifies that SELinux is enforcing (secure) vs permissive/disabled.",
    "Hook Frameworks" to "Detects Xposed, LSPosed, or Frida (hooking frameworks).",
    "Debugger" to "Checks if a debugger is attached to the app process.",
    "Tracer PID" to "Reads /proc/self/status for any tracing process (Frida, etc.).",
    "VPN Detection" to "Detects if a VPN is active (may indicate traffic interception).",
    "Developer Options" to "Checks if Developer Options are enabled (can weaken security).",
    "User CA Certs" to "Searches for user‑installed CA certificates (possible MITM).",
    "USB Debugging" to "Checks if USB debugging is enabled (exposes device).",
    "Accessibility Services" to "Lists apps with Accessibility permissions (potential clickjacking).",
    "Overlay Apps" to "Checks for apps that can draw over other apps (overlay attacks).",
    "Unknown Sources" to "Detects if installation from unknown sources is allowed (sideloading).",
    "Debug Build" to "Verifies that the app is not a debug build (security hardening).",
    "Advanced Emulator" to "Performs deeper emulator detection via system properties and files.",
    "SSL Pinning Health" to "Independently verifies the backend's certificate pin, beyond the OS-level network security config.",
    "TrustManager Tamper Check" to "Detects a globally-installed trust-all SSLContext/TrustManager overriding the platform default.",
    "MITM Proxy Detection" to "Checks for an active system HTTP proxy that could indicate traffic interception.",
    "Root Manager Launch Probe" to "Two-layer check: PackageManager resolution, then a real launch attempt via a different code path if the first layer finds nothing.",
    "Hardware Attestation" to "Generates a hardware-backed key and inspects its TEE/StrongBox attestation certificate for verified-boot state and bootloader lock, independent of any file/package-based check.",
    "Native Library Injection" to "Scans this process's own live memory map and thread list for known hooking-framework footprints (Frida, Xposed/LSPosed), rather than trusting a package-manager query.",
    "Insecure Build Properties" to "Checks ro.secure and ro.debuggable system properties for a whole-OS insecure/debuggable build, beyond this app's own Build Tags/Debug Build checks.",
    "Installer Source" to "Verifies the app was installed via Google Play rather than sideloaded, as a local complement to the Play Integrity licensing verdict.",
    "Frida Server Port Scan" to "Scans for a frida-server listening on its default ports (27042/27043), catching it before it attaches to this specific process.",
    "Magisk Socket Leak" to "Checks /proc/net/unix for magiskd's abstract Unix domain socket, which stays visible even when files/packages are hidden. Note: often blocked by SELinux on Android 10+, in which case this fails open to PASS.",
    "Mount Namespace Leak" to "Checks /proc/self/mountinfo for an OverlayFS mount over /system or /vendor - systemless root's own mount leaking into this app's namespace.",
    "Attestation Key Revocation" to "Checks every certificate in this device's hardware attestation chain against Google's own server-side revocation list - catches a leaked/stolen keybox (e.g. TrickyStore) once Google discovers and revokes it, even if the local Hardware Attestation check above is fooled."
)

val checkRemediation = mapOf(
    "Root Detection" to "Uninstall root management apps (Magisk, SuperSU) or use a stock, unrooted device.",
    "Emulator" to "Run the app on physical hardware rather than an emulator/virtual device.",
    "App Signature" to "Reinstall the official build from the Play Store; a mismatch means this APK was repackaged.",
    "Root Files" to "Remove Magisk/KernelSU or flash a stock, unmodified system image.",
    "Build Tags" to "Install an official release build of the OS rather than a custom/test‑keys ROM.",
    "System Mount" to "Restore /system to read‑only; a writable system partition usually means root access.",
    "BusyBox" to "Uninstall BusyBox or the root tool that installed it.",
    "Bootloader" to "Re‑lock the bootloader via fastboot if you no longer need custom firmware.",
    "SELinux" to "Boot with an OS build that keeps SELinux enforcing; avoid custom kernels that disable it.",
    "Hook Frameworks" to "Uninstall Xposed/LSPosed modules or Frida server before using the app.",
    "Debugger" to "Close any attached debugger and relaunch the app normally.",
    "Tracer PID" to "Stop any process tracing/injection tool (e.g. Frida) attached to the app.",
    "VPN Detection" to "Disable the active VPN if you don't intend to route this app's traffic through it.",
    "Developer Options" to "Turn off Developer Options in Settings if not actively developing.",
    "User CA Certs" to "Remove any user‑installed CA certificates from Settings > Security > Trusted credentials.",
    "USB Debugging" to "Disable USB debugging in Developer Options when not actively debugging.",
    "Accessibility Services" to "Review Settings > Accessibility and disable services you don't recognize or need.",
    "Overlay Apps" to "Revoke \"draw over other apps\" permission from apps that don't need it.",
    "Unknown Sources" to "Disable installation from unknown sources in Settings if not sideloading apps.",
    "Debug Build" to "Install the release build rather than a debuggable/debug build.",
    "Advanced Emulator" to "Run the app on physical hardware; Goldfish/Ranchu traces indicate an emulator.",
    "SSL Pinning Health" to "Reconnect on a trusted network; if this persists, the backend's certificate may have rotated without updating the pinned hash.",
    "TrustManager Tamper Check" to "Remove any Xposed/Frida module or app globally overriding TLS trust (e.g. 'trust all certs' modules).",
    "MITM Proxy Detection" to "Disable any configured HTTP/HTTPS proxy under Wi-Fi settings if you don't intend to route traffic through one.",
    "Root Manager Launch Probe" to "Uninstall the detected root-manager app or use a stock, unrooted device.",
    "Hardware Attestation" to "Use a stock, unmodified boot image with a locked bootloader; a custom/forged attestation chain (e.g. TrickyStore-class tools) can spoof this check on a per-app basis, so treat it as one signal among several, not a sole source of truth.",
    "Native Library Injection" to "Detach any attached Frida session or uninstall the Xposed/LSPosed framework before using the app.",
    "Insecure Build Properties" to "Install an official, secure/production OS build rather than a userdebug/eng image.",
    "Installer Source" to "Install the app from Google Play rather than sideloading, if you need this signal to pass.",
    "Frida Server Port Scan" to "Stop any running frida-server process on the device.",
    "Magisk Socket Leak" to "Uninstall Magisk; magiskd's socket is present whenever its daemon is running.",
    "Mount Namespace Leak" to "Uninstall Magisk/systemless root or flash a stock, unmodified system image.",
    "Attestation Key Revocation" to "Use a stock, unmodified device; a revoked/suspended key means this device's attestation chain relies on a leaked keybox (e.g. TrickyStore) that Google has already flagged."
)

// ============================================================
// MAIN ACTIVITY
// ============================================================
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val themePrefs = getSharedPreferences("nk_prefs", Context.MODE_PRIVATE)
        NkTheme.isDark = themePrefs.getBoolean("dark_theme", true)
        NkCheckMode.mode = try {
            CheckMode.valueOf(themePrefs.getString("check_mode", CheckMode.HIGH.name) ?: CheckMode.HIGH.name)
        } catch (e: IllegalArgumentException) {
            CheckMode.HIGH
        }
        setContent {
            val viewModel: MainViewModel = viewModel()

            NkIntegrityTheme(darkTheme = NkTheme.isDark) {
                Surface(modifier = Modifier.fillMaxSize(), color = GlassBg) {
                    var currentScreen by remember { mutableStateOf(Screen.SECURITY) }

                    Scaffold(
                        modifier = Modifier.fillMaxSize(),
                        containerColor = GlassBg,
                        bottomBar = {
                            NavigationBar(
                                containerColor = GlassSurface,
                                contentColor = TextPrimary
                            ) {
                                NavigationBarItem(
                                    icon = { Icon(Icons.Filled.Shield, contentDescription = "Security") },
                                    label = { Text("Security") },
                                    selected = currentScreen == Screen.SECURITY,
                                    onClick = { currentScreen = Screen.SECURITY }
                                )
                                NavigationBarItem(
                                    icon = { Icon(Icons.Filled.VerifiedUser, contentDescription = "Integrity") },
                                    label = { Text("Integrity") },
                                    selected = currentScreen == Screen.INTEGRITY,
                                    onClick = { currentScreen = Screen.INTEGRITY }
                                )
                                NavigationBarItem(
                                    icon = { Icon(Icons.Filled.PhoneAndroid, contentDescription = "Device") },
                                    label = { Text("Device") },
                                    selected = currentScreen == Screen.DEVICE_INFO,
                                    onClick = { currentScreen = Screen.DEVICE_INFO }
                                )
                                NavigationBarItem(
                                    icon = { Icon(Icons.Filled.FactCheck, contentDescription = "Checks") },
                                    label = { Text("Checks") },
                                    selected = currentScreen == Screen.CHECKS,
                                    onClick = { currentScreen = Screen.CHECKS }
                                )
                            }
                        }
                    ) { innerPadding ->
                        when (currentScreen) {
                            Screen.SECURITY -> {
                                SecurityScreen(
                                    modifier = Modifier.padding(innerPadding),
                                    viewModel = viewModel
                                )
                            }
                            Screen.INTEGRITY -> {
                                IntegrityScreen(
                                    modifier = Modifier.padding(innerPadding),
                                    viewModel = viewModel
                                )
                            }
                            Screen.DEVICE_INFO -> {
                                DeviceInfoScreen(
                                    modifier = Modifier.padding(innerPadding),
                                    context = applicationContext
                                )
                            }
                            Screen.CHECKS -> {
                                AllChecksScreen(
                                    modifier = Modifier.padding(innerPadding),
                                    viewModel = viewModel
                                )
                            }
                        }
                    }
                }
            }
        }
        
        // Wake backend via ViewModel
        // MainViewModel(application).wakeBackend() // Or use a proper initialization
    }
}

// ============================================================
// COMPONENTS
// ============================================================

@Composable
fun GlassCard(
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .shadow(elevation = 8.dp, shape = RoundedCornerShape(16.dp), clip = false)
            .background(GlassCardBg, shape = RoundedCornerShape(16.dp))
            .border(1.dp, GlassBorder, RoundedCornerShape(16.dp)),
        colors = CardDefaults.cardColors(containerColor = Color.Transparent),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            content()
        }
    }
}

@Composable
fun GradientCircularProgress(
    progress: Float,
    modifier: Modifier = Modifier,
    size: androidx.compose.ui.unit.Dp = 100.dp,
    strokeWidth: androidx.compose.ui.unit.Dp = 8.dp
) {
    val gradientColors = listOf(AccentPrimary, AccentSecondary)
    Canvas(modifier = modifier.size(size)) {
        val sweepAngle = progress * 360f
        drawArc(
            color = Color.White.copy(alpha = 0.1f),
            startAngle = -90f,
            sweepAngle = 360f,
            useCenter = false,
            style = Stroke(width = strokeWidth.toPx(), cap = StrokeCap.Round)
        )
        drawArc(
            brush = Brush.sweepGradient(gradientColors),
            startAngle = -90f,
            sweepAngle = sweepAngle,
            useCenter = false,
            style = Stroke(width = strokeWidth.toPx(), cap = StrokeCap.Round)
        )
    }
}

@Composable
fun StatusChip(status: CheckStatus) {
    val (color, label) = when (status) {
        CheckStatus.PASS -> Pair(Success, "PASS")
        CheckStatus.FAIL -> Pair(Danger, "FAIL")
        CheckStatus.WARNING -> Pair(Warning, "WARNING")
    }
    Surface(
        color = color.copy(alpha = 0.15f),
        shape = RoundedCornerShape(20.dp)
    ) {
        Text(
            text = label,
            color = color,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp)
        )
    }
}

@Composable
fun SeverityBadge(severity: CheckSeverity) {
    val color = when (severity) {
        CheckSeverity.HIGH -> Danger
        CheckSeverity.MEDIUM -> Warning
        CheckSeverity.LOW -> TextSecondary
    }
    Surface(
        color = color.copy(alpha = 0.15f),
        shape = RoundedCornerShape(6.dp)
    ) {
        Text(
            text = severity.name,
            color = color,
            fontSize = 10.sp,
            fontWeight = FontWeight.Bold,
            maxLines = 1,
            softWrap = false,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityScreen(
    modifier: Modifier = Modifier,
    viewModel: MainViewModel
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val isLoading by viewModel.isScanning
    val checks by viewModel.lastSecurityResults

    LaunchedEffect(Unit) { 
        if (checks.isEmpty()) {
            viewModel.performScan(context)
        }
    }

    val visibleChecks = checks.filter { NkCheckMode.mode.includes(checkSeverity[it.name] ?: CheckSeverity.MEDIUM) }
    val passCount = visibleChecks.count { it.status == CheckStatus.PASS }
    val total = visibleChecks.size.coerceAtLeast(1)
    val progress = passCount.toFloat() / total
    val problemChecks = visibleChecks.filter { it.status != CheckStatus.PASS }

    Box(modifier = modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(GlassBg)
                .padding(16.dp)
        ) {
            // Header
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(16.dp))
                    .background(Brush.horizontalGradient(listOf(Color(0xFF1A1A2E), Color(0xFF16213E))))
                    .padding(20.dp)
            ) {
                Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.Shield, contentDescription = null, tint = HeaderTextPrimary, modifier = Modifier.size(28.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text("NK Integrity Pro", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold, color = HeaderTextPrimary)
                        Text("Real‑time Security Dashboard", style = MaterialTheme.typography.bodyMedium, color = HeaderTextSecondary)
                    }
                    IconButton(onClick = {
                        NkTheme.isDark = !NkTheme.isDark
                        context.getSharedPreferences("nk_prefs", Context.MODE_PRIVATE)
                            .edit().putBoolean("dark_theme", NkTheme.isDark).apply()
                    }) {
                        Icon(
                            imageVector = if (NkTheme.isDark) Icons.Filled.LightMode else Icons.Filled.DarkMode,
                            contentDescription = "Toggle theme",
                            tint = HeaderTextPrimary
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Check mode selector - filters which checks are shown/counted, doesn't rescan
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                CheckMode.entries.forEach { mode ->
                    val selected = NkCheckMode.mode == mode
                    Surface(
                        modifier = Modifier
                            .weight(1f)
                            .clickable {
                                NkCheckMode.mode = mode
                                context.getSharedPreferences("nk_prefs", Context.MODE_PRIVATE)
                                    .edit().putString("check_mode", mode.name).apply()
                            },
                        color = if (selected) AccentPrimary else GlassCardBg,
                        shape = RoundedCornerShape(10.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, GlassBorder)
                    ) {
                        Text(
                            text = mode.label,
                            color = if (selected) Color.White else TextSecondary,
                            fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
                            fontSize = 13.sp,
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                            modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Score card
            GlassCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    GradientCircularProgress(progress = progress, modifier = Modifier.size(80.dp))
                    Spacer(modifier = Modifier.width(20.dp))
                    Column {
                        Text(text = "${(progress * 100).toInt()}%", style = MaterialTheme.typography.headlineLarge, fontWeight = FontWeight.Bold, color = TextPrimary)
                        Text(text = "$passCount / $total checks passed", style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
                        Text(
                            text = when {
                                progress >= 0.9f -> "✅ SAFE"
                                problemChecks.any { it.status == CheckStatus.FAIL } -> "❌ CRITICAL ISSUES"
                                else -> "⚠️ ATTENTION NEEDED"
                            },
                            color = when {
                                progress >= 0.9f -> Success
                                problemChecks.any { it.status == CheckStatus.FAIL } -> Danger
                                else -> Warning
                            },
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Alert list
            if (problemChecks.isEmpty() && checks.isNotEmpty()) {
                GlassCard {
                    Text("All checks passed. Your device is secure. ✅", style = MaterialTheme.typography.bodyMedium, color = Success)
                }
            } else if (checks.isNotEmpty()) {
                Column {
                    Text(
                        text = "⚠️ Issues Found (${problemChecks.size})",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = if (problemChecks.any { it.status == CheckStatus.FAIL }) Danger else Warning,
                        modifier = Modifier.padding(bottom = 8.dp)
                    )
                    LazyColumn(
                        modifier = Modifier.fillMaxWidth().heightIn(max = 300.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(problemChecks) { check ->
                            val color = if (check.status == CheckStatus.FAIL) Danger else Warning
                            val icon = if (check.status == CheckStatus.FAIL) Icons.Default.Close else Icons.Default.Warning
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(containerColor = GlassCardBg),
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Row(
                                    modifier = Modifier.padding(12.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(24.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Column {
                                        Text(check.name, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Bold, color = TextPrimary)
                                        Text(check.message, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Re‑scan Button
            Button(
                onClick = { viewModel.performScan(context) },
                enabled = !isLoading,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp)
                    .background(
                        Brush.horizontalGradient(listOf(AccentPrimary, AccentSecondary)),
                        shape = RoundedCornerShape(12.dp)
                    ),
                colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent, contentColor = Color.White),
                shape = RoundedCornerShape(12.dp)
            ) {
                Text(if (isLoading) "SCANNING..." else "🔄 RE‑SCAN", fontWeight = FontWeight.Bold)
            }

            Spacer(modifier = Modifier.weight(1f))

            // Footer
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = "NK Integrity Pro v1.1 (Hardened)",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary
                )
                Text(
                    text = "Developed by Nilesh Kale",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary
                )
            }
        }
    }
}

@Composable
fun IntegrityScreen(
    modifier: Modifier = Modifier,
    viewModel: MainViewModel
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val isRunning by viewModel.isIntegrityRunning
    val lastResult by viewModel.lastIntegrityResult
    var checkStatus by remember { mutableStateOf("Idle") }
    var statusMessage by remember { mutableStateOf("Ready to run integrity check.") }

    LaunchedEffect(lastResult) {
        if (lastResult.isNotEmpty()) {
            if (lastResult.contains("❌") || lastResult.contains("Error")) {
                checkStatus = "Error"
                statusMessage = "Check failed. See details below."
            } else {
                checkStatus = "Success"
                statusMessage = "Check completed successfully."
            }
        }
    }
    
    if (isRunning) {
        checkStatus = "Running"
        statusMessage = "Integrity check in progress..."
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(GlassBg)
            .padding(16.dp)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(16.dp))
                .background(Brush.horizontalGradient(listOf(Color(0xFF1A1A2E), Color(0xFF16213E))))
                .padding(16.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.VerifiedUser, contentDescription = null, tint = HeaderTextPrimary, modifier = Modifier.size(28.dp))
                Spacer(modifier = Modifier.width(12.dp))
                Column {
                    Text("Play Integrity", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold, color = HeaderTextPrimary)
                    Text("Cloud attestation via Google", style = MaterialTheme.typography.bodySmall, color = HeaderTextSecondary)
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        GlassCard {
            Column {
                Text("Run Remote Check", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold, color = TextPrimary)
                Text("Verifies device integrity using Google's servers.", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                Spacer(modifier = Modifier.height(12.dp))
                Button(
                    onClick = { viewModel.runPlayIntegrity(context) },
                    enabled = !isRunning,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = AccentPrimary, contentColor = Color.White),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Text(if (isRunning) "RUNNING..." else "▶️ RUN INTEGRITY CHECK", fontWeight = FontWeight.Bold)
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        GlassCard {
            Row(verticalAlignment = Alignment.CenterVertically) {
                val (icon, color) = when (checkStatus) {
                    "Idle" -> Pair("⏸️", TextSecondary)
                    "Running" -> Pair("🔄", AccentSecondary)
                    "Success" -> Pair("✅", Success)
                    "Error" -> Pair("❌", Danger)
                    else -> Pair("⏸️", TextSecondary)
                }
                Text(icon, fontSize = 24.sp)
                Spacer(modifier = Modifier.width(12.dp))
                Column {
                    Text(checkStatus, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, color = color)
                    Text(statusMessage, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        if (lastResult.isNotEmpty()) {
            GlassCard(
                modifier = Modifier.fillMaxSize()
            ) {
                Column {
                    Text("📋 Detailed Report", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold, color = TextPrimary)
                    Spacer(modifier = Modifier.height(8.dp))

                    val lines = lastResult.split("\n")
                    for (line in lines) {
                        when {
                            line.startsWith("☁️") -> {
                                Text(line, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, color = AccentPrimary)
                            }
                            line.startsWith("Nonce:") -> {
                                val status = if (line.contains("✅")) Success else Danger
                                Text(line, style = MonospaceBodyStyle, color = status, modifier = Modifier.padding(start = 8.dp))
                            }
                            line.startsWith("Device Integrity Verdicts:") -> {
                                Text(line, style = MonospaceBodyStyle, color = TextPrimary, modifier = Modifier.padding(start = 8.dp))
                            }
                            line.startsWith("  ✅") -> {
                                Text(line, style = MonospaceBodyStyle, color = Success, modifier = Modifier.padding(start = 16.dp))
                            }
                            line.startsWith("  ❌") -> {
                                Text(line, style = MonospaceBodyStyle, color = Danger, modifier = Modifier.padding(start = 16.dp))
                            }
                            line.startsWith("  ⚠️") -> {
                                Text(line, style = MonospaceBodyStyle, color = Warning, modifier = Modifier.padding(start = 16.dp))
                            }
                            line.startsWith("App Recognition:") || line.startsWith("App Access Risk:") || line.startsWith("Licensing:") -> {
                                Text(line, style = MonospaceBodyStyle, color = TextPrimary, modifier = Modifier.padding(start = 8.dp))
                            }
                            else -> {
                                if (line.isNotBlank()) {
                                    Text(line, style = MonospaceBodyStyle, color = TextSecondary, modifier = Modifier.padding(start = 8.dp))
                                }
                            }
                        }
                    }
                }
            }
        } else {
            GlassCard {
                Text("No integrity check run yet.", style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            }
        }
    }
}

private val sensitiveDeviceInfoKeys = setOf("Android ID", "WiFi MAC Address", "Advertising ID")

private fun maskValue(value: String): String = "•".repeat(value.length.coerceIn(6, 16))

@Composable
fun DeviceInfoScreen(modifier: Modifier = Modifier, context: Context) {
    var deviceInfoItems by remember { mutableStateOf(getDeviceInfo(context)) }
    var sensitiveRevealed by remember { mutableStateOf(false) }

    // Advertising ID must be fetched off the main thread (see fetchAdvertisingIdInfo) - appended
    // once available rather than blocking the initial synchronous getDeviceInfo() above.
    LaunchedEffect(Unit) {
        val adItems = fetchAdvertisingIdInfo(context)
        deviceInfoItems = deviceInfoItems + adItems
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(GlassBg)
            .padding(16.dp)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(16.dp))
                .background(Brush.horizontalGradient(listOf(Color(0xFF1A1A2E), Color(0xFF16213E))))
                .padding(16.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.PhoneAndroid, contentDescription = null, tint = HeaderTextPrimary, modifier = Modifier.size(28.dp))
                Spacer(modifier = Modifier.width(12.dp))
                Column {
                    Text("Device Configuration", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold, color = HeaderTextPrimary)
                    Text("Full hardware & software details", style = MaterialTheme.typography.bodySmall, color = HeaderTextSecondary)
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("Sensitive identifiers are masked by default", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
            TextButton(onClick = { sensitiveRevealed = !sensitiveRevealed }) {
                Text(if (sensitiveRevealed) "Hide" else "Show", color = AccentSecondary, fontWeight = FontWeight.Bold)
            }
        }

        GlassCard(modifier = Modifier.weight(1f)) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                val grouped = deviceInfoItems.groupBy { it.category }
                grouped.forEach { (category, items) ->
                    item {
                        Text(category, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, color = AccentPrimary, modifier = Modifier.padding(top = 8.dp, bottom = 4.dp))
                    }
                    items.forEach { item ->
                        item {
                            val displayValue = if (item.key in sensitiveDeviceInfoKeys && !sensitiveRevealed) {
                                maskValue(item.value)
                            } else {
                                item.value
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(text = item.key, style = MonospaceBodyStyle, color = TextSecondary, modifier = Modifier.weight(1f))
                                Text(text = displayValue, style = MonospaceBodyStyle, color = TextPrimary, modifier = Modifier.weight(1f))
                            }
                            HorizontalDivider(color = TextSecondary.copy(alpha = 0.2f), thickness = 1.dp)
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun AllChecksScreen(
    modifier: Modifier = Modifier,
    viewModel: MainViewModel
) {
    val checks by viewModel.lastSecurityResults
    
    Column(
        modifier = modifier
            .fillMaxSize()
            .background(GlassBg)
            .padding(16.dp)
    ) {
        // Header
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(16.dp))
                .background(Brush.horizontalGradient(listOf(Color(0xFF1A1A2E), Color(0xFF16213E))))
                .padding(16.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.FactCheck, contentDescription = null, tint = HeaderTextPrimary, modifier = Modifier.size(28.dp))
                Spacer(modifier = Modifier.width(12.dp))
                Column {
                    Text("Security Checks", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold, color = HeaderTextPrimary)
                    Text("All available checks with descriptions", style = MaterialTheme.typography.bodySmall, color = HeaderTextSecondary)
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        GlassCard(modifier = Modifier.fillMaxSize()) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                val allCheckNames = checkDescriptions.keys.filter {
                    NkCheckMode.mode.includes(checkSeverity[it] ?: CheckSeverity.MEDIUM)
                }
                items(allCheckNames) { name ->
                    val result = checks.find { it.name == name }
                    val status = result?.status ?: CheckStatus.WARNING
                    val color = when (status) {
                        CheckStatus.PASS -> Success
                        CheckStatus.FAIL -> Danger
                        CheckStatus.WARNING -> Warning
                    }
                    val icon = when (status) {
                        CheckStatus.PASS -> Icons.Default.CheckCircle
                        CheckStatus.FAIL -> Icons.Default.Close
                        CheckStatus.WARNING -> Icons.Default.Warning
                    }
                    var expanded by remember(name) { mutableStateOf(false) }
                    val remediation = checkRemediation[name]
                    val canExpand = status != CheckStatus.PASS && remediation != null

                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .let { m -> if (canExpand) m.clickable { expanded = !expanded } else m },
                        colors = CardDefaults.cardColors(containerColor = GlassCardBg),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(24.dp))
                                Spacer(modifier = Modifier.width(12.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text(
                                            name,
                                            style = MaterialTheme.typography.bodyMedium,
                                            fontWeight = FontWeight.Bold,
                                            color = TextPrimary,
                                            maxLines = 1,
                                            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                                            modifier = Modifier.weight(1f, fill = false)
                                        )
                                        Spacer(modifier = Modifier.width(6.dp))
                                        SeverityBadge(severity = checkSeverity[name] ?: CheckSeverity.MEDIUM)
                                    }
                                    Text(checkDescriptions[name] ?: "", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                                }
                                StatusChip(status = status)
                                if (canExpand) {
                                    Icon(
                                        imageVector = if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                                        contentDescription = if (expanded) "Collapse" else "Expand",
                                        tint = TextSecondary,
                                        modifier = Modifier.padding(start = 4.dp)
                                    )
                                }
                            }
                            if (expanded && remediation != null) {
                                HorizontalDivider(color = TextSecondary.copy(alpha = 0.2f), thickness = 1.dp, modifier = Modifier.padding(vertical = 8.dp))
                                Row {
                                    Icon(Icons.Filled.Build, contentDescription = null, tint = AccentSecondary, modifier = Modifier.size(18.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(remediation, style = MaterialTheme.typography.bodySmall, color = TextPrimary)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@SuppressLint("MissingPermission")
fun getDeviceInfo(context: Context): List<DeviceInfoItem> {
    val items = mutableListOf<DeviceInfoItem>()

    // Device
    items.add(DeviceInfoItem("Device", "Model", Build.MODEL))
    items.add(DeviceInfoItem("Device", "Manufacturer", Build.MANUFACTURER))
    items.add(DeviceInfoItem("Device", "Brand", Build.BRAND))
    items.add(DeviceInfoItem("Device", "Device", Build.DEVICE))
    items.add(DeviceInfoItem("Device", "Product", Build.PRODUCT))
    items.add(DeviceInfoItem("Device", "Hardware", Build.HARDWARE))
    items.add(DeviceInfoItem("Device", "Board", Build.BOARD))
    items.add(DeviceInfoItem("Device", "Android ID", Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) ?: "N/A"))

    // System
    items.add(DeviceInfoItem("System", "Android Version", Build.VERSION.RELEASE))
    items.add(DeviceInfoItem("System", "API Level", Build.VERSION.SDK_INT.toString()))
    items.add(DeviceInfoItem("System", "Build Fingerprint", Build.FINGERPRINT))
    items.add(DeviceInfoItem("System", "Build Date", SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(Build.TIME))))
    items.add(DeviceInfoItem("System", "Build Tags", Build.TAGS ?: "N/A"))
    items.add(DeviceInfoItem("System", "Build Type", Build.TYPE ?: "N/A"))
    items.add(DeviceInfoItem("System", "Build User", Build.USER ?: "N/A"))
    items.add(DeviceInfoItem("System", "Build Host", Build.HOST ?: "N/A"))
    items.add(DeviceInfoItem("System", "Bootloader Version", Build.BOOTLOADER ?: "N/A"))
    items.add(DeviceInfoItem("System", "Radio / Baseband", Build.getRadioVersion() ?: "N/A"))

    // Kernel
    val kernelVersion = try {
        java.io.BufferedReader(java.io.InputStreamReader(Runtime.getRuntime().exec("uname -a").inputStream)).use { it.readText().trim() }
    } catch (e: Exception) { "Unknown" }
    items.add(DeviceInfoItem("Kernel", "Version", kernelVersion))

    // CPU
    val cpuInfo = try {
        java.io.BufferedReader(java.io.FileReader("/proc/cpuinfo")).use { it.readText().trim() }
    } catch (e: Exception) { "Unknown" }
    val cpuSummary = cpuInfo.split("\n").take(5).joinToString("\n")
    items.add(DeviceInfoItem("CPU", "Info (preview)", cpuSummary))

    // Screen
    val metrics = context.resources.displayMetrics
    items.add(DeviceInfoItem("Screen", "Width (px)", metrics.widthPixels.toString()))
    items.add(DeviceInfoItem("Screen", "Height (px)", metrics.heightPixels.toString()))
    items.add(DeviceInfoItem("Screen", "Density (dpi)", metrics.densityDpi.toString()))
    items.add(DeviceInfoItem("Screen", "Scaled Density", metrics.scaledDensity.toString()))

    // Memory
    val memInfo = try {
        java.io.BufferedReader(java.io.FileReader("/proc/meminfo")).use { it.readText().trim() }
    } catch (e: Exception) { "Unknown" }
    val memSummary = memInfo.split("\n").take(3).joinToString("\n")
    items.add(DeviceInfoItem("Memory", "MemInfo (preview)", memSummary))

    // Application
    try {
        val pkg = context.packageManager.getPackageInfo(context.packageName, 0)
        items.add(DeviceInfoItem("Application", "Version Name", pkg.versionName ?: "N/A"))
        val versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pkg.longVersionCode.toString()
        } else {
            @Suppress("DEPRECATION")
            pkg.versionCode.toString()
        }
        items.add(DeviceInfoItem("Application", "Version Code", versionCode))
        val targetSdk = pkg.applicationInfo?.targetSdkVersion ?: 0
        items.add(DeviceInfoItem("Application", "Target SDK", targetSdk.toString()))
        items.add(DeviceInfoItem("Application", "Install Time", SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(pkg.firstInstallTime))))
        items.add(DeviceInfoItem("Application", "Last Update", SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(pkg.lastUpdateTime))))
    } catch (e: Exception) {
        items.add(DeviceInfoItem("Application", "Error", e.message ?: "Unknown"))
    }

    // Environment
    val properties = System.getProperties()
    items.add(DeviceInfoItem("Environment", "Java Version", properties.getProperty("java.version") ?: "Unknown"))
    items.add(DeviceInfoItem("Environment", "OS Name", properties.getProperty("os.name") ?: "Unknown"))

    // Network
    try {
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val connectionInfo = wifiManager.connectionInfo
        val macAddress = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            connectionInfo?.macAddress ?: "N/A"
        } else {
            @Suppress("DEPRECATION")
            connectionInfo?.macAddress ?: "N/A"
        }
        val macDisplay = if (macAddress == "02:00:00:00:00:00") {
            "$macAddress (MAC randomization active)"
        } else {
            macAddress
        }
        items.add(DeviceInfoItem("Network", "WiFi MAC Address", macDisplay))
        val ipAddress = connectionInfo?.ipAddress?.let { intToIp(it) } ?: "Not Connected"
        items.add(DeviceInfoItem("Network", "WiFi IP Address", ipAddress))
    } catch (e: SecurityException) {
        items.add(DeviceInfoItem("Network", "WiFi MAC Address", "Permission Denied"))
        items.add(DeviceInfoItem("Network", "WiFi IP Address", "Permission Denied"))
    } catch (e: Exception) {
        items.add(DeviceInfoItem("Network", "WiFi MAC Address", "Unavailable"))
        items.add(DeviceInfoItem("Network", "WiFi IP Address", "Unavailable"))
    }

    // Identifiers
    // GSF ID is deliberately NOT collected: reading it requires
    // com.google.android.providers.gsf.permission.READ_GSERVICES, a signature-level permission
    // only Google-signed system apps can hold - no third-party app can legitimately read it on
    // modern Android (confirmed: querying the provider without it throws a SecurityException).
    // Android ID and Advertising ID below already cover this category and are properly
    // accessible; attempting a workaround for a platform-restricted identifier is also the kind
    // of thing Play Store review scrutinizes.

    // Advertising ID is intentionally NOT fetched here: AdvertisingIdClient.getAdvertisingIdInfo()
    // is a blocking call that throws IllegalStateException if invoked on the main thread, and
    // getDeviceInfo() is called synchronously via remember{} on the Compose UI thread. Fetched
    // separately and asynchronously in DeviceInfoScreen instead - see fetchAdvertisingIdInfo().

    return items
}

// AdvertisingIdClient.getAdvertisingIdInfo() is a blocking call that throws
// IllegalStateException if invoked on the main thread - kept separate from the synchronous
// getDeviceInfo() above (which runs via remember{} on the Compose UI thread) for exactly that
// reason. Also requires the com.google.android.gms.permission.AD_ID manifest permission to
// return a real (non-zeroed) ID on targetSdk 33+.
private suspend fun fetchAdvertisingIdInfo(context: Context): List<DeviceInfoItem> = withContext(Dispatchers.IO) {
    try {
        val adInfo = AdvertisingIdClient.getAdvertisingIdInfo(context)
        listOf(
            DeviceInfoItem("Identifiers", "Advertising ID", adInfo.id ?: "N/A"),
            DeviceInfoItem("Identifiers", "Ad ID Limit Tracking", adInfo.isLimitAdTrackingEnabled.toString())
        )
    } catch (e: Exception) {
        listOf(DeviceInfoItem("Identifiers", "Advertising ID", "N/A: ${e.message}"))
    }
}

private fun intToIp(ip: Int): String {
    return "${ip and 0xFF}.${ip shr 8 and 0xFF}.${ip shr 16 and 0xFF}.${ip shr 24 and 0xFF}"
}
