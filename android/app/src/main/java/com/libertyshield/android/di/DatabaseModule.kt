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
 * Risk: Key deletion or data partial-clear → DB passphrase mismatch on reopen.
 *       Handled by wipeAndRecreate(): deletes the DB file and regenerates a fresh passphrase.
 *       Historical events are lost but the app starts cleanly.
 * Risk: Passphrase in heap → zeroed after use (JVM GC may delay but best-effort)
 */
package com.libertyshield.android.di

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.room.Room
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.libertyshield.android.data.db.AppDatabase
import com.libertyshield.android.data.db.SensorEventDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import net.sqlcipher.database.SQLiteDatabase
import net.sqlcipher.database.SupportFactory
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    private const val TAG              = "DatabaseModule"
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS        = "ls_db_key"
    private const val PREFS_FILE       = "ls_db_prefs"
    private const val PREF_PASSPHRASE  = "db_passphrase_enc"
    private const val PREF_IV          = "db_passphrase_iv"
    private const val AES_GCM_NOPADDING = "AES/GCM/NoPadding"
    private const val PASSPHRASE_BYTES  = 32
    private const val GCM_TAG_LENGTH    = 128
    private const val DB_NAME           = "liberty_shield.db"

    @Provides
    @Singleton
    fun provideAppDatabase(@ApplicationContext context: Context): AppDatabase {
        return createDatabase(context, allowRetry = true)
    }

    @Provides
    @Singleton
    fun provideSensorEventDao(db: AppDatabase): SensorEventDao = db.sensorEventDao()

    // ===== DATABASE CREATION WITH RECOVERY =====

    /**
     * Creates the encrypted Room database.
     *
     * If the first attempt fails (passphrase mismatch after a partial data-clear or
     * reinstall with Keystore key still present), wipes the database file plus the
     * stored passphrase and tries again with a freshly generated passphrase.
     * Historical events are lost, but the app stays functional.
     *
     * If even the recovery attempt fails, the exception is re-thrown so Hilt fails fast
     * with a clear stack trace rather than a cryptic later crash.
     */
    private fun createDatabase(context: Context, allowRetry: Boolean): AppDatabase {
        val passphrase = getOrCreatePassphrase(context)
        return try {
            buildDatabase(context, passphrase)
        } catch (e: Throwable) {
            Log.e(TAG, "AppDatabase.create() failed: ${e.message}", e)
            passphrase.fill(0)

            if (allowRetry) {
                Log.w(TAG, "Attempting database recovery — wiping DB and regenerating passphrase")
                try {
                    wipeDatabase(context)
                } catch (wipeEx: Exception) {
                    Log.e(TAG, "Failed to wipe database during recovery: ${wipeEx.message}")
                }
                createDatabase(context, allowRetry = false)  // one retry, no further recursion
            } else {
                Log.e(TAG, "Database recovery failed — rethrowing")
                throw e
            }
        } finally {
            passphrase.fill(0)
        }
    }

    private fun buildDatabase(context: Context, passphrase: ByteArray): AppDatabase {
        // loadLibs is idempotent — called here as a safety net for any path that bypasses
        // LibertyShieldApp.onCreate() (e.g., instrumented tests, process resurrection).
        SQLiteDatabase.loadLibs(context)
        val factory = SupportFactory(passphrase)
        return Room.databaseBuilder(
            context.applicationContext,
            AppDatabase::class.java,
            DB_NAME
        )
            .openHelperFactory(factory)
            .fallbackToDestructiveMigration()
            .build()
    }

    /**
     * Deletes the SQLite database files AND the stored encrypted passphrase so that
     * the next call to getOrCreatePassphrase() generates a fresh one.
     */
    private fun wipeDatabase(context: Context) {
        val dbFile = context.getDatabasePath(DB_NAME)
        val filesToDelete = listOf(
            dbFile,
            File("${dbFile.absolutePath}-shm"),
            File("${dbFile.absolutePath}-wal")
        )
        for (f in filesToDelete) {
            if (f.exists()) {
                val deleted = f.delete()
                Log.i(TAG, "Deleted ${f.name}: $deleted")
            }
        }
        // Clear stored passphrase so getOrCreatePassphrase() generates a new one
        try {
            val prefs = context.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)
            prefs.edit().remove(PREF_PASSPHRASE).remove(PREF_IV).apply()
            // Also try the encrypted prefs fallback file
            context.getSharedPreferences("${PREFS_FILE}_fallback", Context.MODE_PRIVATE)
                .edit().remove(PREF_PASSPHRASE).remove(PREF_IV).apply()
        } catch (e: Exception) {
            Log.w(TAG, "Could not clear passphrase prefs during wipe: ${e.message}")
        }
        Log.i(TAG, "Database wipe complete")
    }

    // ===== PASSPHRASE MANAGEMENT =====

    private fun getOrCreatePassphrase(context: Context): ByteArray {
        val prefs = getEncryptedPrefs(context)
        val encPassphraseB64 = prefs.getString(PREF_PASSPHRASE, null)
        val ivB64 = prefs.getString(PREF_IV, null)

        return if (encPassphraseB64 != null && ivB64 != null) {
            try {
                decryptPassphrase(encPassphraseB64, ivB64)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to decrypt existing passphrase — generating new one. DB will be re-keyed.", e)
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
            .setUserAuthenticationRequired(false)
            .build()

        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    private fun getEncryptedPrefs(context: Context): android.content.SharedPreferences {
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
            Log.e(TAG, "EncryptedSharedPreferences init failed — falling back to plaintext prefs. " +
                "This may happen on first boot on some OEM devices.", e)
            context.getSharedPreferences("${PREFS_FILE}_fallback", Context.MODE_PRIVATE)
        }
    }
}
