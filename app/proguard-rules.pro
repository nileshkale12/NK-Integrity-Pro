# Project specific ProGuard rules

# Keep Play Integrity API classes
-keep class com.google.android.play.core.integrity.** { *; }

# Keep Compose internal classes that might be stripped
-keep class androidx.compose.material.icons.** { *; }

# Preserve line numbers for crash reporting
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# Optimization rules
-repackageclasses ''
-allowaccessmodification
-optimizations !code/simplification/arithmetic,!field/*,!class/merging/*

# Keep JNI entry points if you add any C++ code later
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# NOT keeping com.nk.integritypro.** wholesale on purpose: this is a security/anti-tamper app,
# so letting R8 actually obfuscate/shrink its own detection logic in release builds is a real
# hardening benefit, not just app-size optimization - a blanket keep rule here would ship every
# check's implementation fully readable in the release APK. Nothing in this app currently uses
# reflection into ITS OWN classes (JSON handling is manual via org.json.JSONObject, not a
# reflection-based serializer) - if a future feature needs specific classes preserved, add a
# narrowly-scoped -keep for just that class/member, not the whole package.
