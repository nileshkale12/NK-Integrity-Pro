package com.nk.integritypro.ui.theme

import androidx.compose.ui.graphics.Color

data class NkColorSet(
    val background: Color,
    val surface: Color,
    val cardBackground: Color,
    val cardBorder: Color,
    val accentPrimary: Color,
    val accentSecondary: Color,
    val success: Color,
    val warning: Color,
    val danger: Color,
    val textPrimary: Color,
    val textSecondary: Color
)

val NkDarkColors = NkColorSet(
    background = Color(0xFF0A0E17),
    surface = Color(0xFF131A26),
    cardBackground = Color.White.copy(alpha = 0.05f),
    cardBorder = Color.White.copy(alpha = 0.10f),
    accentPrimary = Color(0xFF6C63FF),
    accentSecondary = Color(0xFF00D4FF),
    success = Color(0xFF00E676),
    warning = Color(0xFFFFAB00),
    danger = Color(0xFFFF1744),
    textPrimary = Color(0xFFFFFFFF),
    textSecondary = Color(0xFFB0BEC5)
)

val NkLightColors = NkColorSet(
    background = Color(0xFFF5F6FA),
    surface = Color(0xFFFFFFFF),
    cardBackground = Color.Black.copy(alpha = 0.04f),
    cardBorder = Color.Black.copy(alpha = 0.08f),
    accentPrimary = Color(0xFF5B4FE0),
    accentSecondary = Color(0xFF0089B3),
    success = Color(0xFF12894F),
    warning = Color(0xFFB26A00),
    danger = Color(0xFFD32F2F),
    textPrimary = Color(0xFF1A1F29),
    textSecondary = Color(0xFF5B6472)
)
