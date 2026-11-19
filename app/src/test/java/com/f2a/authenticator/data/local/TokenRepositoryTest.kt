package com.f2a.authenticator.data.local

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import com.f2a.authenticator.crypto.SecretCipher
import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.Tag
import com.f2a.authenticator.data.model.TokenType
import com.f2a.authenticator.data.model.Workspace
import com.f2a.authenticator.security.Clock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

@OptIn(ExperimentalCoroutinesApi::class)
class TokenRepositoryTest {

    private class InMemoryVaultStorage(
        @Volatile var docJson: String? = null,
        @Volatile var bakJson: String? = null,
        @Volatile var legacy: LegacyVaultSections? = null
    ) : VaultDocumentStorage {
        override fun readDocumentJson(): String? = docJson
        override fun readBackupDocumentJson(): String? = bakJson
        override fun hasAnyDocumentFile(): Boolean = !docJson.isNullOrBlank() || !bakJson.isNullOrBlank()
        override fun writeDocumentJson(json: String) {
            if (!docJson.isNullOrBlank()) {
                bakJson = docJson
            }
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
        val failAllEncrypts = AtomicBoolean(false)

        override fun encrypt(plainText: String): SecretCipher.EncryptResult {
            encryptCalls.incrementAndGet()
            if (failAllEncrypts.get()) {
                return SecretCipher.EncryptResult.Failed("transient keystore error")
            }
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
    fun lockInMemory_racingWithConcurrentWrites_neverOverwritesDiskWithEmptyVault() = runBlocking {
        val storage = InMemoryVaultStorage()
        val cipher = FakeSecretCipher()
        val clock = FakeClock()
        val repo = TokenRepository(storage, cipher, clock, Dispatchers.IO, isDebugBuild = false)
        repo.unlockAndLoad()

        val initial = (1..20).map { i ->
            AuthToken(id = "base_$i", issuer = "Svc$i", accountName = "u$i@x.com", secret = "JBSWY3DPEHPK3PXP")
        }
        repo.addTokens(initial)

        // 并发写入与反复 lockInMemory() 竞争，绝不能写出仅含新增条目的空/半截库
        coroutineScope {
            val writer = launch(Dispatchers.Default) {
                repeat(40) { idx ->
                    repo.addTokensDedup(
                        listOf(
                            AuthToken(
                                id = "race_$idx",
                                issuer = "RaceSvc",
                                accountName = "r$idx@x.com",
                                secret = "JBSWY3DPEHPK3PXP"
                            )
                        )
                    )
                }
            }
            val locker = launch(Dispatchers.Default) {
                repeat(10) {
                    repo.lockInMemory()
                }
            }
            writer.join()
            locker.join()
        }
        repo.close()

        val verifyRepo = TokenRepository(storage, cipher, clock, Dispatchers.IO, isDebugBuild = false)
        verifyRepo.unlockAndLoad()
        assertTrue(
            "Existing 20 tokens must never be lost on lock/write race, actual=${verifyRepo.tokens.value.size}",
            verifyRepo.tokens.value.size >= 20
        )
        assertTrue(verifyRepo.workspaces.value.isNotEmpty())
        verifyRepo.close()
    }

    @Test
    fun corruptPrimaryDocument_recoversFromBak_andDualCorruptEntersReadOnlyMode() = runTest {
        val storage = InMemoryVaultStorage()
        val cipher = FakeSecretCipher()
        val clock = FakeClock()
        val dispatcher = UnconfinedTestDispatcher(testScheduler)

        val seedRepo = TokenRepository(storage, cipher, clock, dispatcher, isDebugBuild = false)
        seedRepo.unlockAndLoad()
        seedRepo.addToken(AuthToken(id = "t1", issuer = "GitHub", accountName = "a@b.com", secret = "JBSWY3DPEHPK3PXP"))
        seedRepo.addToken(AuthToken(id = "t2", issuer = "Google", accountName = "c@d.com", secret = "JBSWY3DPEHPK3PXP"))
        seedRepo.close()

        // 破坏主文件，保留有效 .bak -> 应自动从 .bak 恢复至少 1 条记录并自愈主文件
        assertNotNull(storage.bakJson)
        storage.docJson = "{CORRUPTED_JSON_TRUNCATED"

        val recoveredRepo = TokenRepository(storage, cipher, clock, dispatcher, isDebugBuild = false)
        recoveredRepo.unlockAndLoad()
        assertFalse(recoveredRepo.vaultLoadCorrupted.value)
        assertTrue(recoveredRepo.tokens.value.isNotEmpty())
        recoveredRepo.close()

        // 主备同时损坏 -> 置 vaultLoadCorrupted = true，且拒绝空库覆写磁盘
        val corruptMarker = "{BOTH_CORRUPT"
        storage.docJson = corruptMarker
        storage.bakJson = "{ALSO_CORRUPT"
        val corruptRepo = TokenRepository(storage, cipher, clock, dispatcher, isDebugBuild = false)
        assertTrue(corruptRepo.hasStoredEncryptedTokens())
        corruptRepo.unlockAndLoad()
        assertTrue(corruptRepo.vaultLoadCorrupted.value)
        assertTrue(corruptRepo.tokens.value.isEmpty())

        corruptRepo.addToken(AuthToken(id = "new_1", issuer = "New", accountName = "x", secret = "JBSWY3DPEHPK3PXP"))
        assertEquals(corruptMarker, storage.docJson)
        corruptRepo.close()
    }

    @Test
    fun encryptFailure_doesNotPublishOrOverwriteExistingDiskTokens() = runTest {
        val storage = InMemoryVaultStorage()
        val cipher = FakeSecretCipher()
        val clock = FakeClock()
        val dispatcher = UnconfinedTestDispatcher(testScheduler)

        val repo = TokenRepository(storage, cipher, clock, dispatcher, isDebugBuild = false)
        repo.unlockAndLoad()
        repo.addToken(AuthToken(id = "t1", issuer = "AWS", accountName = "root", secret = "JBSWY3DPEHPK3PXP"))
        val savedJson = storage.docJson

        cipher.failAllEncrypts.set(true)
        repo.addToken(AuthToken(id = "t2", issuer = "Cloudflare", accountName = "ops", secret = "GEZDGNBVGY3TQOJQ"))

        // 加密失败时绝不能将新明文写入磁盘，也不应使内存与磁盘分叉
        assertEquals(savedJson, storage.docJson)
        assertEquals(1, repo.tokens.value.size)
        assertFalse(storage.docJson?.contains("GEZDGNBVGY3TQOJQ") == true)
        repo.close()
    }

    @Test
    fun concurrentMutations_500OperationsAcross4Coroutines_noLostUpdates() = runBlocking {
        val storage = InMemoryVaultStorage()
        val cipher = FakeSecretCipher()
        val clock = FakeClock()
        val repo = TokenRepository(storage, cipher, clock, Dispatchers.IO, isDebugBuild = false)
        repo.unlockAndLoad()

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
        val first = repo.tokens.value.first()
        repo.updateToken(first.copy(counter = first.counter + 1))
        assertEquals(0, cipher.encryptCalls.get())

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

        cipher.encryptCalls.set(0)
        repo.togglePin("legacy_1")
        assertEquals(0, cipher.encryptCalls.get())
        assertTrue(storage.docJson?.contains("RAW_CORRUPT_CIPHER") == true)
        repo.close()
    }

    @Test
    fun advanceHotp_concurrentCallsNeverLoseIncrements_andIgnoresTotp() = runBlocking {
        val storage = InMemoryVaultStorage()
        val cipher = FakeSecretCipher()
        val clock = FakeClock()
        val repo = TokenRepository(storage, cipher, clock, Dispatchers.IO, isDebugBuild = false)
        repo.unlockAndLoad()
        repo.addTokens(
            listOf(
                AuthToken(
                    id = "hotp_1",
                    issuer = "GitHub",
                    accountName = "hotp@test.com",
                    secret = "JBSWY3DPEHPK3PXP",
                    type = TokenType.HOTP,
                    counter = 0L
                ),
                AuthToken(
                    id = "totp_1",
                    issuer = "Google",
                    accountName = "totp@test.com",
                    secret = "JBSWY3DPEHPK3PXP",
                    type = TokenType.TOTP,
                    counter = 0L
                )
            )
        )

        coroutineScope {
            repeat(50) {
                launch(Dispatchers.Default) {
                    repo.advanceHotp("hotp_1")
                    repo.advanceHotp("totp_1")
                }
            }
        }

        assertEquals(50L, repo.tokens.value.first { it.id == "hotp_1" }.counter)
        assertEquals(0L, repo.tokens.value.first { it.id == "totp_1" }.counter)
        repo.close()
    }

    @Test
    fun deleteAllTags_staysEmptyOnReload_andDeleteWorkspaceMigratesTokens() = runTest {
        val storage = InMemoryVaultStorage()
        val cipher = FakeSecretCipher()
        val clock = FakeClock()
        val dispatcher = UnconfinedTestDispatcher(testScheduler)

        val repo = TokenRepository(storage, cipher, clock, dispatcher, isDebugBuild = false)
        repo.unlockAndLoad()
        repo.addToken(
            AuthToken(
                id = "t1",
                workspaceId = Workspace.DEFAULT_WORK.id,
                issuer = "GitLab",
                accountName = "dev",
                secret = "JBSWY3DPEHPK3PXP",
                tagIds = listOf(Tag.TAG_MAIN.id)
            )
        )

        for (tag in repo.tags.value.toList()) {
            repo.deleteTag(tag.id)
        }
        assertTrue(repo.tags.value.isEmpty())
        assertTrue(repo.tokens.value.single().tagIds.isEmpty())

        repo.deleteWorkspace(Workspace.DEFAULT_WORK.id)
        assertEquals(Workspace.DEFAULT_PERSONAL.id, repo.tokens.value.single().workspaceId)
        repo.close()

        val reloaded = TokenRepository(storage, cipher, clock, dispatcher, isDebugBuild = false)
        reloaded.unlockAndLoad()
        assertTrue(reloaded.tags.value.isEmpty())
        assertEquals(Workspace.DEFAULT_PERSONAL.id, reloaded.tokens.value.single().workspaceId)
        reloaded.close()
    }

    @Test
    fun fileVaultDocumentStorage_realFileAtomicWriteAndBakRecovery() {
        val tempDir = Files.createTempDirectory("f2a-storage-test").toFile()
        tempDir.deleteOnExit()
        val fakeCtx = object : ContextWrapper(null) {
            override fun getApplicationContext(): Context = this
            override fun getFilesDir(): File = File(tempDir, "files").apply { mkdirs() }
            override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences =
                throw UnsupportedOperationException()
            override fun getApplicationInfo(): ApplicationInfo = ApplicationInfo()
        }

        val fileStorage = FileVaultDocumentStorage(fakeCtx)
        fileStorage.writeDocumentJson("""{"version":1}""")
        assertEquals("""{"version":1}""", fileStorage.readDocumentJson())
        assertEquals(null, fileStorage.readBackupDocumentJson())

        fileStorage.writeDocumentJson("""{"version":2}""")
        assertEquals("""{"version":2}""", fileStorage.readDocumentJson())
        assertEquals("""{"version":1}""", fileStorage.readBackupDocumentJson())
        assertTrue(fileStorage.hasAnyDocumentFile())
    }
}
