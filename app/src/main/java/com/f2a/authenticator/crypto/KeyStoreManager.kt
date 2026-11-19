package com.f2a.authenticator.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.InvalidKeyException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.ProviderException
import java.security.UnrecoverableKeyException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * 基于 Android KeyStore 硬件级 TEE/StrongBox 安全芯片的 AES-256-GCM 加密引擎。
 * 确保即使 root 设备或外部备份提取，没有系统硬件私钥也无法解密 Secret。
 */
object KeyStoreManager : SecretCipher {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val MASTER_KEY_ALIAS = "My2FA_Hardware_MasterKey_v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH = 128
    private const val GCM_TAG_BYTES = GCM_TAG_LENGTH / 8
    private const val IV_LENGTH = 12

    @Volatile
    private var destroyed = false

    private var cachedKeyStore: KeyStore? = null
    private var cachedSecretKey: SecretKey? = null
    private val lock = Any()

    init {
        try {
            synchronized(lock) {
                ensureKeyExistsLocked()
            }
        } catch (_: Exception) {
            // 极端情况下（如销毁后重启）初始化失败不应在类加载时直接崩溃
        }
    }

    private fun getKeyStoreLocked(): KeyStore {
        cachedKeyStore?.let { return it }
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        cachedKeyStore = ks
        return ks
    }

    private fun buildKeyGenSpec(useStrongBox: Boolean): KeyGenParameterSpec {
        val builder = KeyGenParameterSpec.Builder(
            MASTER_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)

        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        return builder.build()
    }

    private fun ensureKeyExistsLocked() {
        if (destroyed) throw IllegalStateException("Master key has been destroyed")
        val keyStore = getKeyStoreLocked()
        if (!keyStore.containsAlias(MASTER_KEY_ALIAS)) {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
            )
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    keyGenerator.init(buildKeyGenSpec(useStrongBox = true))
                    keyGenerator.generateKey()
                } catch (e: Exception) {
                    // 部分 OEM 设备 StrongBox HAL 异常可能抛出 ProviderException 或 KeyStoreException，统一降级至 TEE
                    if (e is StrongBoxUnavailableException ||
                        e is ProviderException ||
                        e is KeyStoreException
                    ) {
                        keyGenerator.init(buildKeyGenSpec(useStrongBox = false))
                        keyGenerator.generateKey()
                    } else {
                        throw e
                    }
                }
            } else {
                keyGenerator.init(buildKeyGenSpec(useStrongBox = false))
                keyGenerator.generateKey()
            }
            cachedSecretKey = null
        }
    }

    private fun getSecretKeyLocked(): SecretKey {
        if (destroyed) throw IllegalStateException("Master key has been destroyed")
        cachedSecretKey?.let { return it }
        ensureKeyExistsLocked()
        val key = getKeyStoreLocked().getKey(MASTER_KEY_ALIAS, null) as? SecretKey
            ?: throw UnrecoverableKeyException("Master key alias missing")
        cachedSecretKey = key
        return key
    }

    private fun getSecretKey(): SecretKey = synchronized(lock) {
        getSecretKeyLocked()
    }

    private fun invalidateCachedKey() {
        synchronized(lock) {
            cachedSecretKey = null
        }
    }

    /**
     * 【终极销毁】：在互斥锁内永久删除硬件主密钥，并置 destroyed 禁止后续重建。
     */
    override fun destroyMasterKey() {
        synchronized(lock) {
            destroyed = true
            cachedSecretKey = null
            try {
                val keyStore = getKeyStoreLocked()
                if (keyStore.containsAlias(MASTER_KEY_ALIAS)) {
                    keyStore.deleteEntry(MASTER_KEY_ALIAS)
                }
            } catch (_: Exception) {
            } finally {
                cachedKeyStore = null
            }
        }
    }

    /**
     * 加密明文，输出格式：Base64(IV + CipherText + Tag)。
     * 捕获 KeyStore / 状态异常并封装为 EncryptResult.Failed，绝不裸抛崩溃；结束后擦除临时明文字节数组。
     */
    override fun encrypt(plainText: String): SecretCipher.EncryptResult {
        if (plainText.isEmpty()) return SecretCipher.EncryptResult.Ok("")
        var plainBytes: ByteArray? = null
        return try {
            val key = getSecretKey()
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv
            plainBytes = plainText.toByteArray(StandardCharsets.UTF_8)
            val encryptedBytes = cipher.doFinal(plainBytes)

            val combined = ByteArray(iv.size + encryptedBytes.size)
            System.arraycopy(iv, 0, combined, 0, iv.size)
            System.arraycopy(encryptedBytes, 0, combined, iv.size, encryptedBytes.size)

            SecretCipher.EncryptResult.Ok(Base64.encodeToString(combined, Base64.NO_WRAP))
        } catch (e: UnrecoverableKeyException) {
            invalidateCachedKey()
            SecretCipher.EncryptResult.Failed(e.message ?: "key unrecoverable")
        } catch (e: InvalidKeyException) {
            invalidateCachedKey()
            SecretCipher.EncryptResult.Failed(e.message ?: "key invalid")
        } catch (e: KeyStoreException) {
            invalidateCachedKey()
            SecretCipher.EncryptResult.Failed(e.message ?: "keystore error")
        } catch (e: IllegalStateException) {
            SecretCipher.EncryptResult.Failed(e.message ?: "keystore destroyed")
        } catch (e: Exception) {
            SecretCipher.EncryptResult.Failed(e.message ?: e.javaClass.simpleName)
        } finally {
            plainBytes?.fill(0)
        }
    }

    fun encryptOrNull(plainText: String): String? = when (val result = encrypt(plainText)) {
        is SecretCipher.EncryptResult.Ok -> result.cipherTextBase64
        is SecretCipher.EncryptResult.Failed -> null
    }

    /**
     * 解密 Base64 字符串，最小长度校验为 IV(12) + GCM_TAG(16) = 28 字节；结束后擦除临时明文字节数组。
     */
    override fun decrypt(cipherTextBase64: String): SecretCipher.DecryptResult {
        if (cipherTextBase64.isEmpty()) return SecretCipher.DecryptResult.Empty
        var decryptedBytes: ByteArray? = null
        return try {
            val combined = Base64.decode(cipherTextBase64, Base64.NO_WRAP)
            if (combined.size < IV_LENGTH + GCM_TAG_BYTES) {
                return SecretCipher.DecryptResult.Corrupt("ciphertext too short")
            }

            val iv = ByteArray(IV_LENGTH)
            val cipherText = ByteArray(combined.size - IV_LENGTH)
            System.arraycopy(combined, 0, iv, 0, IV_LENGTH)
            System.arraycopy(combined, IV_LENGTH, cipherText, 0, cipherText.size)

            val cipher = Cipher.getInstance(TRANSFORMATION)
            val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
            cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), spec)

            decryptedBytes = cipher.doFinal(cipherText)
            SecretCipher.DecryptResult.Ok(String(decryptedBytes, StandardCharsets.UTF_8))
        } catch (_: AEADBadTagException) {
            SecretCipher.DecryptResult.Corrupt("bad GCM tag")
        } catch (e: UnrecoverableKeyException) {
            invalidateCachedKey()
            SecretCipher.DecryptResult.KeyInvalid(e.message ?: "key unrecoverable")
        } catch (e: InvalidKeyException) {
            invalidateCachedKey()
            SecretCipher.DecryptResult.KeyInvalid(e.message ?: "key invalid")
        } catch (e: KeyStoreException) {
            invalidateCachedKey()
            SecretCipher.DecryptResult.KeyInvalid(e.message ?: "keystore error")
        } catch (e: IllegalStateException) {
            SecretCipher.DecryptResult.KeyInvalid(e.message ?: "keystore destroyed")
        } catch (e: Exception) {
            SecretCipher.DecryptResult.Corrupt(e.javaClass.simpleName)
        } finally {
            decryptedBytes?.fill(0)
        }
    }
}
