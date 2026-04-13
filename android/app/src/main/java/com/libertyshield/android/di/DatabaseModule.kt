/*
 * Threat model: Database encryption module.
 * Manages SQLCipher passphrase lifecycle via Android Keystore.
 *
 * Key derivation strategy:
 *   1. Generate a random 256-bit AES key in Android Keystore (alias "ls_db_key")
 *   2. Use this key to encrypt a random 32-byte database passphrase
 *   3. Store the encrypted passphrase in EncryptedSharedPreferences (also Keystore-backed)
 *   4. On each app start: decrypt passphrase, open DB, zero passphrase bytes
 *
 * Risk: Key not hardware-backed on all devices → acceptable; SW Keystore still protects
 *       against file-system-only attackers (no root)
 * Risk: Key deletion → DB becomes permanently unreadable; acceptable as security guarantee
 * Risk: Passphrase in heap → zeroed after use (JVM GC may delay but best-effort)
 */
package com.libertyshield.android.di

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.libertyshield.android.data.db.AppDatabase
import com.libertyshield.android.data.db.SensorEventDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    private const val TAG = "DatabaseModule"
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS = "ls_db_key"
    private const val PREFS_FILE = "ls_db_prefs"
    private const val PREF_PASSPHRASE = "db_passphrase_enc"
    private const val PREF_IV = "db_passphrase_iv"
    private const val AES_GCM_NOPADDING = "AES/GCM/NoPadding"
    private const val PASSPHRASE_BYTES = 32
    private const val GCM_TAG_LENGTH = 128

    @Provides
    @Singleton
    fun provideAppDatabase(@ApplicationContext context: Context): AppDatabase {
        val passphrase = getOrCreatePassphrase(context)
        return try {
            AppDatabase.create(context, passphrase)
        } catch (e: Throwable) {
            Log.e(TAG, "AppDatabase.create() failed — UnsatisfiedLinkError or Keystore issue: ${e.message}", e)
            throw e
        } finally {
            // Zero passphrase bytes after DB is opened (or on failure)
            passphrase.fill(0)
        }
    }

    @Provides
    @Singleton
    fun provideSensorEventDao(db: AppDatabase): SensorEventDao = db.sensorEventDao()

    // ===== PASSPHRASE MANAGEMENT =====

    /**
     * Returns the database passphrase, generating and encrypting it on first call.
     *
     * The caller MUST zero the returned ByteArray after use.
     */
    private fun getOrCreatePassphrase(context: Context): ByteArray {
        val prefs = getEncryptedPrefs(context)
        val encPassphraseB64 = prefs.getString(PREF_PASSPHRASE, null)
        val ivB64 = prefs.getString(PREF_IV, null)

        return if (encPassphraseB64 != null && ivB64 != null) {
            // Decrypt existing passphrase
            try {
                decryptPassphrase(encPassphraseB64, ivB64)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to decrypt existing passphrase — generating new one. DB will be destroyed.", e)
                generateAndStoreNewPassphrase(prefs)
            }
        } else {
            Log.i(TAG, "First launch — generating new DB passphrase")
            generateAndStoreNewPassphrase(prefs)
        }
    }

    private fun generateAndStoreNewPassphrase(prefs: android.content.SharedPreferences): ByteArray {
        val passphrase = java.security.SecureRandom().generateSeed(PASSPHRASE_BYTES)
        val (encPassphrase, iv) = encryptPassphrase(passphrase)
        prefs.edit()
            .putString(PREF_PASSPHRASE, Base64.encodeToString(encPassphrase, Base64.NO_WRAP))
            .putString(PREF_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
            .apply()
        return passphrase
    }

    private fun encryptPassphrase(passphrase: ByteArray): Pair<ByteArray, ByteArray> {
        val key = getOrCreateKeystoreKey()
        val cipher = Cipher.getInstance(AES_GCM_NOPADDING)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val encrypted = cipher.doFinal(passphrase)
        return Pair(encrypted, iv)
    }

    private fun decryptPassphrase(encPassphraseB64: String, ivB64: String): ByteArray {
        val encPassphrase = Base64.decode(encPassphraseB64, Base64.NO_WRAP)
        val iv = Base64.decode(ivB64, Base64.NO_WRAP)
        val key = getOrCreateKeystoreKey()
        val cipher = Cipher.getInstance(AES_GCM_NOPADDING)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        return cipher.doFinal(encPassphrase)
    }

    private fun getOrCreateKeystoreKey(): SecretKey {
        val keystore = KeyStore.getInstance(KEYSTORE_PROVIDER).also { it.load(null) }

        if (keystore.containsAlias(KEY_ALIAS)) {
            return (keystore.getKey(KEY_ALIAS, null) as SecretKey)
        }

        Log.i(TAG, "Generating new Keystore key: $KEY_ALIAS")
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            KEYSTORE_PROVIDER
        )
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(false) // no biometric gate — service runs headless
            .build()

        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    private fun getEncryptedPrefs(context: Context): android.content.SharedPreferences {
        // Attempt 1: full Keystore-backed encrypted prefs.
        // setRequestStrongBoxBacked(false) avoids StrongBox failures on Samsung/Xiaomi
        // devices where the secure enclave is present but unreliable on first boot.
        return try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .setRequestStrongBoxBacked(false)
                .build()
            EncryptedSharedPreferences.create(
                context,
                PREFS_FILE,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: Exception) {
            Log.e(TAG, "EncryptedSharedPreferences init failed — generating fresh DB passphrase. " +
                "This may happen on first launch on some OEM devices.", e)
            // Attempt 2: plaintext fallback prefs so the DB passphrase can still be
            // generated and stored. Security is degraded but the app stays functional.
            // A fresh passphrase will be generated in generateAndStoreNewPassphrase().
            context.getSharedPreferences("${PREFS_FILE}_fallback", android.content.Context.MODE_PRIVATE)
        }
    }
}
