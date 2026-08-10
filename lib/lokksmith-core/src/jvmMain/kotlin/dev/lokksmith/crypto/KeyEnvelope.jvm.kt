/*
 * Copyright 2026 Sven Jacobs
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package dev.lokksmith.crypto

import dev.lokksmith.PlatformContext
import dev.lokksmith.ensureSecureDirectory
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.operations.IvAuthenticatedCipher
import dev.whyoleg.cryptography.random.CryptographyRandom
import java.io.File
import java.nio.file.Files
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Desktop [KeyEnvelope]. The key is a random AES-256 key saved as a file in the user-private data
 * directory. No hardware isolation here — it's only as safe as the folder's file permissions.
 */
internal actual class KeyEnvelope
actual constructor(
    platformContext: PlatformContext,
    alias: String,
) {

    private val provider = CryptographyProvider.Default
    private val random = CryptographyRandom.Default
    private val dataDirectory: File = platformContext.dataDirectory
    private val kekFile: File = dataDirectory.resolve("$alias.kek")

    private val mutex = Mutex()
    private var cipher: IvAuthenticatedCipher? = null

    actual suspend fun encrypt(dek: ByteArray): ByteArray = cipher().encrypt(dek)

    actual suspend fun decrypt(wrapped: ByteArray): ByteArray = cipher().decrypt(wrapped)

    private suspend fun cipher(): IvAuthenticatedCipher =
        cipher ?: mutex.withLock { cipher ?: buildCipher().also { cipher = it } }

    private suspend fun buildCipher(): IvAuthenticatedCipher {
        val kekBytes = loadOrCreateKek()
        val key =
            provider.get(AES.GCM).keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, kekBytes)
        return key.cipher()
    }

    private fun loadOrCreateKek(): ByteArray {
        if (kekFile.exists()) return kekFile.readBytes()
        ensureSecureDirectory(dataDirectory.toPath())
        val kek = random.nextBytes(KEK_SIZE_BYTES)
        // Create the file owner-only where the platform supports POSIX permissions.
        runCatching {
            Files.createFile(
                kekFile.toPath(),
                java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                    java.util.EnumSet.of(
                        java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                        java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                    )
                ),
            )
        }
        kekFile.writeBytes(kek)
        return kek
    }

    private companion object {
        const val KEK_SIZE_BYTES = 32 // AES-256
    }
}
