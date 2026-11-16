package com.f2a.authenticator.crypto

interface SecretCipher {
    sealed class DecryptResult {
        data class Ok(val value: String) : DecryptResult()
        object Empty : DecryptResult()
        data class Corrupt(val reason: String) : DecryptResult()
        data class KeyInvalid(val reason: String) : DecryptResult()
    }

    sealed class EncryptResult {
        data class Ok(val cipherTextBase64: String) : EncryptResult()
        data class Failed(val reason: String) : EncryptResult()
    }

    fun encrypt(plainText: String): EncryptResult
    fun decrypt(cipherTextBase64: String): DecryptResult
    fun destroyMasterKey()
}
