package com.f2a.authenticator.ui.screens.scan

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PhotoLibrary
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.min
import com.f2a.authenticator.ui.theme.CobaltPrimaryDark
import com.f2a.authenticator.ui.theme.IconSize
import com.f2a.authenticator.ui.theme.LocalSemanticColors
import com.f2a.authenticator.ui.theme.Radius
import com.f2a.authenticator.ui.theme.Space
import com.f2a.authenticator.ui.theme.Touch
import com.f2a.authenticator.ui.theme.Type

@Composable
fun ScanOverlayLayer(modifier: Modifier = Modifier) {
    val scrimColor = LocalSemanticColors.current.scrim
    val bracketColor = CobaltPrimaryDark
    val transition = rememberInfiniteTransition(label = "scan_line")
    val lineProgress by transition.animateFloat(
        initialValue = 0.08f,
        targetValue = 0.92f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 2200, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "scan_line_y"
    )

    BoxWithConstraints(modifier = modifier.fillMaxSize()) {
        val windowSize = min(264.dp, min(maxWidth, maxHeight) * 0.72f)
        val side = ((maxWidth - windowSize) / 2).coerceAtLeast(0.dp)
        val vertical = ((maxHeight - windowSize) / 2).coerceAtLeast(0.dp)

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(vertical)
                .background(scrimColor)
        )
        Box(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .fillMaxWidth()
                .height(vertical)
                .background(scrimColor)
        )
        Box(
            modifier = Modifier
                .align(Alignment.CenterStart)
                .width(side)
                .height(windowSize)
                .background(scrimColor)
        )
        Box(
            modifier = Modifier
                .align(Alignment.CenterEnd)
                .width(side)
                .height(windowSize)
                .background(scrimColor)
        )

        Box(
            modifier = Modifier
                .align(Alignment.Center)
                .size(windowSize)
                .drawWithContent {
                    drawContent()
                    val stroke = 2.5.dp.toPx()
                    val arm = (windowSize * 0.11f).toPx().coerceAtMost(28.dp.toPx())
                    val r = Radius.XS.toPx()
                    val w = size.width
                    val h = size.height
                    val style = Stroke(width = stroke, cap = StrokeCap.Round)

                    drawRect(
                        color = Color.White.copy(alpha = 0.12f),
                        style = Stroke(width = 1.dp.toPx())
                    )

                    fun bracket(cx: Float, cy: Float, dx: Float, dy: Float) {
                        val path = Path().apply {
                            moveTo(cx + dx * arm, cy)
                            lineTo(cx + dx * r, cy)
                            quadraticTo(cx, cy, cx, cy + dy * r)
                            lineTo(cx, cy + dy * arm)
                        }
                        drawPath(path, color = bracketColor, style = style)
                    }
                    bracket(0f, 0f, 1f, 1f)
                    bracket(w, 0f, -1f, 1f)
                    bracket(0f, h, 1f, -1f)
                    bracket(w, h, -1f, -1f)
                }
        ) {
            // 克制单线精密扫描指示
            Canvas(modifier = Modifier.fillMaxSize()) {
                val y = size.height * lineProgress
                val inset = 12.dp.toPx()
                drawLine(
                    brush = Brush.horizontalGradient(
                        listOf(
                            Color.Transparent,
                            bracketColor.copy(alpha = 0.65f),
                            Color.Transparent
                        )
                    ),
                    start = Offset(inset, y),
                    end = Offset(size.width - inset, y),
                    strokeWidth = 1.5.dp.toPx()
                )
            }
        }
    }
}

@Composable
fun CameraPermissionGuide(
    hasRequestedPermission: Boolean,
    canAskAgain: Boolean,
    onRequest: () -> Unit,
    onOpenSettings: () -> Unit,
    onPickFromGallery: () -> Unit,
    onManualInput: () -> Unit,
    modifier: Modifier = Modifier
) {
    val permanentlyDenied = hasRequestedPermission && !canAskAgain
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = Space.X3L),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            imageVector = Icons.Default.Lock,
            contentDescription = null,
            tint = Color.White.copy(alpha = 0.85f),
            modifier = Modifier.size(IconSize.Hero)
        )
        Spacer(modifier = Modifier.height(Space.L))
        Text(
            text = if (permanentlyDenied) "相机权限已被关闭" else "需要相机权限",
            color = Color.White,
            style = Type.TitleSection,
            textAlign = TextAlign.Center
        )
        Spacer(modifier = Modifier.height(Space.S))
        Text(
            text = if (permanentlyDenied) {
                "相机权限已被永久拒绝，请前往系统设置开启，或从相册选择二维码图片。"
            } else {
                "开启相机权限以扫描 2FA 二维码，也可从相册选图或手动输入。"
            },
            color = Color.White.copy(alpha = 0.78f),
            style = Type.BodyM,
            textAlign = TextAlign.Center
        )
        Spacer(modifier = Modifier.height(Space.XL))
        Button(
            onClick = if (permanentlyDenied) onOpenSettings else onRequest,
            shape = RoundedCornerShape(Radius.M),
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = Touch.MinTarget)
        ) {
            Text(
                text = if (permanentlyDenied) "去系统设置开启" else "授权相机",
                fontWeight = FontWeight.SemiBold
            )
        }
        Spacer(modifier = Modifier.height(Space.M))
        OutlinedButton(
            onClick = onPickFromGallery,
            shape = RoundedCornerShape(Radius.M),
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = Touch.MinTarget),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White)
        ) {
            Icon(Icons.Default.PhotoLibrary, contentDescription = null, modifier = Modifier.size(IconSize.S))
            Spacer(modifier = Modifier.width(Space.S))
            Text("从相册选择二维码", fontWeight = FontWeight.SemiBold)
        }
        Spacer(modifier = Modifier.height(Space.M))
        OutlinedButton(
            onClick = onManualInput,
            shape = RoundedCornerShape(Radius.M),
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = Touch.MinTarget),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White)
        ) {
            Text("手动输入代码", fontWeight = FontWeight.SemiBold)
        }
    }
}
