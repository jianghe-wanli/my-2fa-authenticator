package com.f2a.authenticator.data.local

import com.f2a.authenticator.crypto.SecretCipher
import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.TokenType
import com.f2a.authenticator.data.model.Workspace
import com.f2a.authenticator.security.Clock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class TokenRepositoryTest {

    private class InMemoryVaultStorage(
        @Volatile var docJson: String? = null,
        @Volatile var legacy: LegacyVaultSections? = null
    ) : VaultDocumentStorage {
        override fun readDocumentJson(): String? = docJson
        override fun writeDocumentJson(json: String) {
            docJson = json
        }
        override fun hasLegacyTokens(): Boolean = !legacy?.tokensJson.isNullOrBlank()
        override fun readLegacySections(): LegacyVaultSections? = legacy
        override fun clearLegacy() {
            legacy = null
        }
    }

    private class FakeSecretCipher : SecretCipher {
        val encryptCalls = AtomicInteger(0)
        val decryptCalls = AtomicInteger(0)
        @Volatile var failDecryptFor: Set<String> = emptySet()

        override fun encrypt(plainText: String): SecretCipher.EncryptResult {
            encryptCalls.incrementAndGet()
            return SecretCipher.EncryptResult.Ok("ENC:$plainText")
        }

        override fun decrypt(cipherTextBase64: String): SecretCipher.DecryptResult {
            decryptCalls.incrementAndGet()
            if (cipherTextBase64.isBlank()) return SecretCipher.DecryptResult.Empty
            if (cipherTextBase64 in failDecryptFor) return SecretCipher.DecryptResult.Corrupt("corrupt")
            return if (cipherTextBase64.startsWith("ENC:")) {
                SecretCipher.DecryptResult.Ok(cipherTextBase64.removePrefix("ENC:"))
            } else {
                SecretCipher.DecryptResult.Corrupt("bad prefix")
            }
        }

        override fun destroyMasterKey() {}
    }

    private class FakeClock(initialMs: Long = 1_700_000_000_000L) : Clock {
        val nowMs = AtomicLong(initialMs)
        override fun elapsedRealtimeMs(): Long = nowMs.get()
        override fun currentTimeMillis(): Long = nowMs.get()
    }

    @Test
    fun lazyDecryption_initDoesNotCallDecrypt_unlockAndLoadDecryptsOnDemand() = runTest {
        val storage = InMemoryVaultStorage()
        val cipher = FakeSecretCipher()
        val clock = FakeClock()
        val dispatcher = UnconfinedTestDispatcher(testScheduler)

        // 先写入一条密文到存储
        val seedRepo = TokenRepository(storage, cipher, clock, dispatcher, isDebugBuild = false)
        seedRepo.unlockAndLoad()
        seedRepo.addToken(AuthToken(id = "t1", issuer = "GitHub", accountName = "a@b.com", secret = "JBSWY3DPEHPK3PXP"))
        seedRepo.close()

        cipher.decryptCalls.set(0)
        val repo = TokenRepository(storage, cipher, clock, dispatcher, isDebugBuild = false)
        assertFalse(repo.isLoaded.value)
        assertTrue(repo.tokens.value.isEmpty())
        assertEquals(0, cipher.decryptCalls.get())
        assertTrue(repo.hasStoredEncryptedTokens())
        assertEquals(0, cipher.decryptCalls.get())

        repo.unlockAndLoad()
        assertTrue(repo.isLoaded.value)
        assertEquals(1, cipher.decryptCalls.get())
        assertEquals("JBSWY3DPEHPK3PXP", repo.tokens.value.single().secret)
        repo.close()
    }

    @Test
    fun wipeInMemoryState_clearsAllFlowsAndBlocksSubsequentWrites() = runTest {
        val storage = InMemoryVaultStorage()
        val cipher = FakeSecretCipher()
        val clock = FakeClock()
        val dispatcher = UnconfinedTestDispatcher(testScheduler)

        val repo = TokenRepository(storage, cipher, clock, dispatcher, isDebugBuild = false)
        repo.unlockAndLoad()
        repo.addToken(AuthToken(id = "t1", issuer = "AWS", accountName = "root", secret = "JBSWY3DPEHPK3PXP"))
        val docBeforeWipe = storage.docJson

        repo.wipeInMemoryState()
        assertFalse(repo.isLoaded.value)
        assertTrue(repo.tokens.value.isEmpty())
        assertTrue(repo.trashedTokens.value.isEmpty())
        assertTrue(repo.workspaces.value.isEmpty())
        assertTrue(repo.tags.value.isEmpty())
        assertFalse(repo.hasStoredEncryptedTokens())

        // 胁迫清空后禁止写回磁盘或恢复内存状态
        repo.addToken(AuthToken(id = "t2", issuer = "Decoy", accountName = "x", secret = "JBSWY3DPEHPK3PXP"))
        repo.unlockAndLoad()
        assertTrue(repo.tokens.value.isEmpty())
        assertEquals(docBeforeWipe, storage.docJson)
        repo.close()
    }

    @Test
    fun lockInMemory_clearsPlaintextAndAllowsReloadOnUnlock() = runTest {
        val storage = InMemoryVaultStorage()
        val cipher = FakeSecretCipher()
        val clock = FakeClock()
        val dispatcher = UnconfinedTestDispatcher(testScheduler)

        val repo = TokenRepository(storage, cipher, clock, dispatcher, isDebugBuild = false)
        repo.unlockAndLoad()
        repo.addToken(AuthToken(id = "t1", issuer = "Google", accountName = "u@g.com", secret = "JBSWY3DPEHPK3PXP"))

        repo.lockInMemory()
        assertFalse(repo.isLoaded.value)
        assertTrue(repo.tokens.value.isEmpty())
        assertTrue(repo.hasStoredEncryptedTokens())

        repo.unlockAndLoad()
        assertTrue(repo.isLoaded.value)
        assertEquals(1, repo.tokens.value.size)
        assertEquals("JBSWY3DPEHPK3PXP", repo.tokens.value.single().secret)
        repo.close()
    }

    @Test
    fun concurrentMutations_500OperationsAcross4Coroutines_noLostUpdates() = runBlocking {
        val storage = InMemoryVaultStorage()
        val cipher = FakeSecretCipher()
        val clock = FakeClock()
        val repo = TokenRepository(storage, cipher, clock, Dispatchers.IO, isDebugBuild = false)
        repo.unlockAndLoad()

        // 4 个协程共执行 500 次并发写（每协程 125 次 addToken）
        coroutineScope {
            repeat(4) { worker ->
                launch(Dispatchers.Default) {
                    repeat(125) { idx ->
                        val id = "w${worker}_$idx"
                        repo.addToken(
                            AuthToken(
                                id = id,
                                issuer = "Issuer$worker",
                                accountName = "user$idx@test.com",
                                secret = "JBSWY3DPEHPK3PXP"
                            )
                        )
                        if (idx % 5 == 0) {
                            repo.togglePin(id)
                        }
                    }
                }
            }
        }

        assertEquals(500, repo.tokens.value.size)
        assertEquals(100, repo.tokens.value.count { it.isPinned })
        repo.close()

        // 重新从磁盘加载校验完全一致
        val reloaded = TokenRepository(storage, cipher, clock, Dispatchers.IO, isDebugBuild = false)
        reloaded.unlockAndLoad()
        assertEquals(500, reloaded.tokens.value.size)
        assertEquals(100, reloaded.tokens.value.count { it.isPinned })
        reloaded.close()
    }

    @Test
    fun encCachePreheatedOnUnlock_avoidsFullReEncryptionOnSingleUpdate() = runTest {
        val storage = InMemoryVaultStorage()
        val cipher = FakeSecretCipher()
        val clock = FakeClock()
        val dispatcher = UnconfinedTestDispatcher(testScheduler)

        val setupRepo = TokenRepository(storage, cipher, clock, dispatcher, isDebugBuild = false)
        setupRepo.unlockAndLoad()
        val batch = (1..200).map { i ->
            AuthToken(
                id = "tok_$i",
                issuer = "Svc$i",
                accountName = "u$i",
                secret = "JBSWY3DPEHPK3PXP",
                type = TokenType.HOTP,
                counter = 0L
            )
        }
        setupRepo.addTokens(batch)
        setupRepo.close()

        cipher.encryptCalls.set(0)
        val repo = TokenRepository(storage, cipher, clock, dispatcher, isDebugBuild = false)
        repo.unlockAndLoad()
        // 仅更新 counter（密钥未变），预热缓存命中 -> 0 次 encrypt
        val first = repo.tokens.value.first()
        repo.updateToken(first.copy(counter = first.counter + 1))
        assertEquals(0, cipher.encryptCalls.get())

        // 更新单条 secret -> 仅对这一条调用 1 次 encrypt（而非 200 次）
        repo.updateToken(first.copy(secret = "GEZDGNBVGY3TQOJQ"))
        assertEquals(1, cipher.encryptCalls.get())
        repo.close()
    }

    @Test
    fun softDelete_restore_and_purgeExpiredTrashAfter7Days() = runTest {
        val storage = InMemoryVaultStorage()
        val cipher = FakeSecretCipher()
        val clock = FakeClock(initialMs = 1_000_000_000L)
        val dispatcher = UnconfinedTestDispatcher(testScheduler)

        val repo = TokenRepository(storage, cipher, clock, dispatcher, isDebugBuild = false)
        repo.unlockAndLoad()
        repo.addTokens(
            listOf(
                AuthToken(id = "t_keep", issuer = "Keep", accountName = "a", secret = "JBSWY3DPEHPK3PXP"),
                AuthToken(id = "t_expire", issuer = "Expire", accountName = "b", secret = "JBSWY3DPEHPK3PXP")
            )
        )

        repo.softDeleteToken("t_keep")
        repo.softDeleteToken("t_expire")
        assertTrue(repo.tokens.value.isEmpty())
        assertEquals(2, repo.trashedTokens.value.size)

        repo.restoreToken("t_keep")
        assertEquals(1, repo.tokens.value.size)
        assertEquals(1, repo.trashedTokens.value.size)

        // 推进 7 天，触发自动清理
        clock.nowMs.addAndGet(TokenRepository.DEFAULT_TRASH_RETENTION_MS)
        repo.purgeExpiredTrash()
        assertTrue(repo.trashedTokens.value.isEmpty())
        assertEquals("t_keep", repo.tokens.value.single().id)
        repo.close()
    }

    @Test
    fun addTokensDedup_skipsDuplicateIdAndBusinessKey() = runTest {
        val storage = InMemoryVaultStorage()
        val cipher = FakeSecretCipher()
        val clock = FakeClock()
        val dispatcher = UnconfinedTestDispatcher(testScheduler)

        val repo = TokenRepository(storage, cipher, clock, dispatcher, isDebugBuild = false)
        repo.unlockAndLoad()
        val t1 = AuthToken(
            id = "id_1",
            workspaceId = Workspace.DEFAULT_PERSONAL.id,
            issuer = "GitHub",
            accountName = "alice@example.com",
            secret = "JBSWY3DPEHPK3PXP"
        )
        val (added1, skipped1) = repo.addTokensDedup(listOf(t1))
        assertEquals(1, added1)
        assertEquals(0, skipped1)

        val dupById = t1.copy(accountName = "other@example.com")
        val dupByBizKey = AuthToken(
            id = "id_2",
            workspaceId = Workspace.DEFAULT_PERSONAL.id,
            issuer = " github ",
            accountName = "ALICE@example.com ",
            secret = "JBSWY3DPEHPK3PXP"
        )
        val fresh = AuthToken(
            id = "id_3",
            workspaceId = Workspace.DEFAULT_WORK.id,
            issuer = "GitHub",
            accountName = "alice@example.com",
            secret = "JBSWY3DPEHPK3PXP"
        )
        val (added2, skipped2) = repo.addTokensDedup(listOf(dupById, dupByBizKey, fresh))
        assertEquals(1, added2)
        assertEquals(2, skipped2)
        assertEquals(2, repo.tokens.value.size)
        repo.close()
    }

    @Test
    fun gsonMissingFieldsAndCorruptSecret_normalizedWithoutNpe_andSecretInvalidNeverReEncrypted() = runTest {
        // 构造缺失 tagIds/type/workspaceId/period 及含未知枚举 "FUTURE_ALGO" 的历史 JSON
        val legacyTokensJson = """
            [
              {
                "id": "legacy_1",
                "issuer": "OldSvc",
                "accountName": "u1",
                "secret": "ENC:JBSWY3DPEHPK3PXP",
                "type": "FUTURE_ALGO"
              },
              {
                "id": "corrupt_1",
                "issuer": "BrokenSvc",
                "accountName": "u2",
                "secret": "RAW_CORRUPT_CIPHER"
              }
            ]
        """.trimIndent()
        val storage = InMemoryVaultStorage(
            legacy = LegacyVaultSections(
                workspacesJson = null,
                tagsJson = null,
                tokensJson = legacyTokensJson
            )
        )
        val cipher = FakeSecretCipher().apply {
            failDecryptFor = setOf("RAW_CORRUPT_CIPHER")
        }
        val clock = FakeClock()
        val dispatcher = UnconfinedTestDispatcher(testScheduler)

        val repo = TokenRepository(storage, cipher, clock, dispatcher, isDebugBuild = false)
        repo.unlockAndLoad()

        val loaded = repo.tokens.value
        assertEquals(2, loaded.size)

        val legacyToken = loaded.first { it.id == "legacy_1" }
        assertEquals(TokenType.TOTP, legacyToken.type)
        assertEquals(emptyList<String>(), legacyToken.tagIds)
        assertEquals(30, legacyToken.period)
        assertEquals(6, legacyToken.digits)
        assertEquals(Workspace.DEFAULT_PERSONAL.id, legacyToken.workspaceId)
        assertFalse(legacyToken.secretInvalid)
        assertEquals("JBSWY3DPEHPK3PXP", legacyToken.secret)

        val corruptToken = loaded.first { it.id == "corrupt_1" }
        assertTrue(corruptToken.secretInvalid)
        assertEquals("RAW_CORRUPT_CIPHER", corruptToken.secret)

        // 触发保存时，corruptToken 绝不能被二次加密
        cipher.encryptCalls.set(0)
        repo.togglePin("legacy_1")
        assertEquals(0, cipher.encryptCalls.get())
        assertTrue(storage.docJson?.contains("RAW_CORRUPT_CIPHER") == true)
        repo.close()
    }

    @Test
    fun advanceHotp_concurrentCallsNeverLoseIncrements() = runBlocking {
        val storage = InMemoryVaultStorage()
        val cipher = FakeSecretCipher()
        val clock = FakeClock()
        val repo = TokenRepository(storage, cipher, clock, Dispatchers.IO, isDebugBuild = false)
        repo.unlockAndLoad()
        repo.addToken(
            AuthToken(
                id = "hotp_1",
                issuer = "GitHub",
                accountName = "hotp@test.com",
                secret = "JBSWY3DPEHPK3PXP",
                type = TokenType.HOTP,
                counter = 0L
            )
        )

        coroutineScope {
            repeat(50) {
                launch(Dispatchers.Default) {
                    repo.advanceHotp("hotp_1")
                }
            }
        }

        assertEquals(50L, repo.tokens.value.single().counter)
        repo.close()
    }
}
