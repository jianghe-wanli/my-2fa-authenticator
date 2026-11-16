package com.f2a.authenticator.ui.screens.scan

import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import java.nio.ByteBuffer
import java.util.EnumMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.min

/**
 * 实例级 YUV 二维码分析器（V2-UI-22：复用缓冲绑定实例生命周期，退出扫码页调用 release() 释放内存）。
 */
class QrFrameAnalyzer(
    private val isProcessingQr: AtomicBoolean,
    private val onQrDetected: (String) -> Unit
) : ImageAnalysis.Analyzer {

    @Volatile
    private var reuseYBytes: ByteArray = ByteArray(0)
    @Volatile
    private var reuseRotated: ByteArray = ByteArray(0)
    private var frameCounter = 0

    private val qrReader = MultiFormatReader().apply {
        val hints = EnumMap<DecodeHintType, Any>(DecodeHintType::class.java).apply {
            put(DecodeHintType.POSSIBLE_FORMATS, listOf(BarcodeFormat.QR_CODE))
            put(DecodeHintType.TRY_HARDER, true)
            put(DecodeHintType.ALSO_INVERTED, true)
            put(DecodeHintType.CHARACTER_SET, "UTF-8")
        }
        setHints(hints)
    }

    override fun analyze(imageProxy: ImageProxy) {
        try {
            if (isProcessingQr.get()) return
            frameCounter++
            if (frameCounter % 2 != 0) return

            val qrContent = decodeQrFromImageProxy(imageProxy)
            if (!qrContent.isNullOrBlank()) {
                onQrDetected(qrContent)
            }
        } finally {
            imageProxy.close()
        }
    }

    fun release() {
        reuseYBytes = ByteArray(0)
        reuseRotated = ByteArray(0)
    }

    private fun decodeQrFromImageProxy(image: ImageProxy): String? {
        return try {
            val plane = image.planes[0]
            val buffer: ByteBuffer = plane.buffer
            buffer.rewind()

            val rowStride = plane.rowStride
            val pixelStride = plane.pixelStride
            val width = image.width
            val height = image.height

            val needed = width * height
            val existingY = reuseYBytes
            val yBytes = if (existingY.size >= needed) {
                existingY
            } else {
                ByteArray(needed).also { reuseYBytes = it }
            }

            if (pixelStride == 1 && rowStride == width) {
                buffer.get(yBytes, 0, needed)
            } else {
                val rowBuffer = ByteArray(rowStride)
                for (row in 0 until height) {
                    buffer.position(row * rowStride)
                    val bytesToRead = if (row == height - 1) {
                        min(buffer.remaining(), (width - 1) * pixelStride + 1)
                    } else {
                        min(buffer.remaining(), rowStride)
                    }
                    buffer.get(rowBuffer, 0, bytesToRead)
                    if (pixelStride == 1) {
                        System.arraycopy(rowBuffer, 0, yBytes, row * width, width)
                    } else {
                        for (col in 0 until width) {
                            yBytes[row * width + col] = rowBuffer[col * pixelStride]
                        }
                    }
                }
            }

            val (rotatedData, finalW, finalH) = when (image.imageInfo.rotationDegrees) {
                90 -> {
                    val rotated = ensureRotatedBuffer(needed)
                    for (y in 0 until height) {
                        val rowOffset = y * width
                        val targetCol = height - y - 1
                        for (x in 0 until width) {
                            rotated[x * height + targetCol] = yBytes[rowOffset + x]
                        }
                    }
                    Triple(rotated, height, width)
                }
                180 -> {
                    val rotated = ensureRotatedBuffer(needed)
                    val lastIdx = needed - 1
                    for (i in 0 until needed) {
                        rotated[i] = yBytes[lastIdx - i]
                    }
                    Triple(rotated, width, height)
                }
                270 -> {
                    val rotated = ensureRotatedBuffer(needed)
                    for (y in 0 until height) {
                        val rowOffset = y * width
                        for (x in 0 until width) {
                            rotated[(width - x - 1) * height + y] = yBytes[rowOffset + x]
                        }
                    }
                    Triple(rotated, height, width)
                }
                else -> Triple(yBytes, width, height)
            }

            val cropSize = (min(finalW, finalH) * 0.75f).toInt()
            val cropLeft = (finalW - cropSize) / 2
            val cropTop = (finalH - cropSize) / 2
            val croppedSource = PlanarYUVLuminanceSource(
                rotatedData, finalW, finalH, cropLeft, cropTop, cropSize, cropSize, false
            )
            decodeSourceMultiPass(croppedSource)?.let { return it }

            val fullSource = PlanarYUVLuminanceSource(
                rotatedData, finalW, finalH, 0, 0, finalW, finalH, false
            )
            decodeSourceMultiPass(fullSource)
        } catch (_: Exception) {
            null
        }
    }

    private fun ensureRotatedBuffer(needed: Int): ByteArray {
        val existing = reuseRotated
        return if (existing.size >= needed) {
            existing
        } else {
            ByteArray(needed).also { reuseRotated = it }
        }
    }

    private fun decodeSourceMultiPass(source: PlanarYUVLuminanceSource): String? {
        try {
            return qrReader.decodeWithState(BinaryBitmap(GlobalHistogramBinarizer(source))).text
        } catch (_: Exception) {
        } finally {
            qrReader.reset()
        }
        try {
            return qrReader.decodeWithState(BinaryBitmap(HybridBinarizer(source))).text
        } catch (_: Exception) {
        } finally {
            qrReader.reset()
        }
        return null
    }
}
