package com.nk.integritypro.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.Color

object NkTheme {
    var isDark by mutableStateOf(true)
    val colors: NkColorSet get() = if (isDark) NkDarkColors else NkLightColors
}

@Composable
fun NkIntegrityTheme(darkTheme: Boolean = NkTheme.isDark, content: @Composable () -> Unit) {
    val colors = if (darkTheme) NkDarkColors else NkLightColors
    val scheme = if (darkTheme) {
        darkColorScheme(
            background = colors.background,
            surface = colors.surface,
            primary = colors.accentPrimary,
            onPrimary = Color.White,
            onBackground = colors.textPrimary,
            onSurface = colors.textPrimary
        )
    } else {
        lightColorScheme(
            background = colors.background,
            surface = colors.surface,
            primary = colors.accentPrimary,
            onPrimary = Color.White,
            onBackground = colors.textPrimary,
            onSurface = colors.textPrimary
        )
    }
    MaterialTheme(colorScheme = scheme, typography = NkTypography, content = content)
}
