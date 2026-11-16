package com.f2a.authenticator.ui.utils

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.net.Uri
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import java.util.EnumMap
import kotlin.math.max

/**
 * 原生 ZXing 二维码渲染与静态图片解码工具（从 GoogleMigrationEncoder 剥离纯 UI/Bitmap 职责）。
 */
object QrBitmapRenderer {

    fun renderQrBitmap(content: String, sizePx: Int = 720): Bitmap? {
        if (content.isBlank() || sizePx <= 0) return null
        return try {
            val hints = mapOf(
                EncodeHintType.MARGIN to 2,
                EncodeHintType.CHARACTER_SET to "UTF-8"
            )
            val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, sizePx, sizePx, hints)
            val w = matrix.width
            val h = matrix.height
            val pixels = IntArray(w * h)
            for (y in 0 until h) {
                for (x in 0 until w) {
                    pixels[y * w + x] = if (matrix.get(x, y)) Color.BLACK else Color.WHITE
                }
            }
            Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888).apply {
                setPixels(pixels, 0, w, 0, 0, w, h)
            }
        } catch (_: Exception) {
            null
        }
    }

    fun decodeQrFromBitmap(bitmap: Bitmap): String? {
        return try {
            val scaled = scaleBitmapIfNeeded(bitmap, maxDim = 1440)
            val w = scaled.width
            val h = scaled.height
            val pixels = IntArray(w * h)
            scaled.getPixels(pixels, 0, w, 0, 0, w, h)
            if (scaled !== bitmap) scaled.recycle()

            // RGBLuminanceSource 会忽略 Alpha 通道，将透明背景压平至白底避免透明 PNG 全黑失败
            for (i in pixels.indices) {
                val argb = pixels[i]
                val a = (argb ushr 24) and 0xFF
                if (a < 255) {
                    val r = (((argb ushr 16) and 0xFF) * a + 255 * (255 - a)) / 255
                    val g = (((argb ushr 8) and 0xFF) * a + 255 * (255 - a)) / 255
                    val b = ((argb and 0xFF) * a + 255 * (255 - a)) / 255
                    pixels[i] = (0xFF shl 24) or (r shl 16) or (g shl 8) or b
                }
            }

            val source = RGBLuminanceSource(w, h, pixels)
            val hints = EnumMap<DecodeHintType, Any>(DecodeHintType::class.java).apply {
                put(DecodeHintType.POSSIBLE_FORMATS, listOf(BarcodeFormat.QR_CODE))
                put(DecodeHintType.TRY_HARDER, true)
                put(DecodeHintType.ALSO_INVERTED, true)
                put(DecodeHintType.CHARACTER_SET, "UTF-8")
            }
            val reader = MultiFormatReader().apply { setHints(hints) }

            try {
                return reader.decodeWithState(BinaryBitmap(HybridBinarizer(source))).text
            } catch (_: Exception) {
                reader.reset()
            }
            try {
                return reader.decodeWithState(BinaryBitmap(GlobalHistogramBinarizer(source))).text
            } catch (_: Exception) {
                reader.reset()
            }
            null
        } catch (_: Exception) {
            null
        }
    }

    fun decodeQrFromUri(context: Context, uri: Uri): String? {
        return try {
            val boundsOpts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            context.contentResolver.openInputStream(uri)?.use { stream ->
                BitmapFactory.decodeStream(stream, null, boundsOpts)
            }
            val maxSide = max(boundsOpts.outWidth, boundsOpts.outHeight)
            var sampleSize = 1
            while (maxSide / sampleSize > 1600) {
                sampleSize *= 2
            }

            val decodeOpts = BitmapFactory.Options().apply {
                inSampleSize = sampleSize
                inPreferredConfig = Bitmap.Config.ARGB_8888
            }
            val bitmap = context.contentResolver.openInputStream(uri)?.use { stream ->
                BitmapFactory.decodeStream(stream, null, decodeOpts)
            } ?: return null
            try {
                decodeQrFromBitmap(bitmap)
            } finally {
                bitmap.recycle()
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun scaleBitmapIfNeeded(bitmap: Bitmap, maxDim: Int): Bitmap {
        val longest = max(bitmap.width, bitmap.height)
        if (longest <= maxDim) return bitmap
        val ratio = maxDim.toFloat() / longest.toFloat()
        val newW = (bitmap.width * ratio).toInt().coerceAtLeast(1)
        val newH = (bitmap.height * ratio).toInt().coerceAtLeast(1)
        return Bitmap.createScaledBitmap(bitmap, newW, newH, true)
    }
}
