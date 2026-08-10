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

/**
 * Wraps and unwraps the data-encryption key (DEK) with a platform key kept in secure storage. Only
 * the wrapped DEK is ever persisted — the key-wrapping half of envelope encryption for
 * [SnapshotCipher].
 */
internal expect class KeyEnvelope(platformContext: PlatformContext, alias: String) {

    /** Wraps [dek] with the platform key, creating that key on first use. */
    suspend fun encrypt(dek: ByteArray): ByteArray

    /**
     * Unwraps a value from [encrypt].
     *
     * @throws Exception if the platform key is gone (e.g. cleared from secure storage) or the input
     *   isn't a valid wrapped DEK. Treat this as key loss.
     */
    suspend fun decrypt(wrapped: ByteArray): ByteArray
}
