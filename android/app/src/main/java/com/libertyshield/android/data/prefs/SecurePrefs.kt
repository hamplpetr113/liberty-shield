/*
 * Threat model: Secure configuration storage.
 * Uses EncryptedSharedPreferences backed by Android Keystore.
 * Risk: Preferences exfiltration → AES-256 encryption via Keystore
 * Risk: Key extraction → hardware-backed Keystore on supported devices
 * Risk: Concurrent read/write during init → lazy + synchronized init
 */
package com.libertyshield.android.data.prefs

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.libertyshield.android.BuildConfig
import dagger.hilt.android.qualifiers.ApplicationContext
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class SecurePrefs @Inject constructor(
    @ApplicationContext private val context: Context
) {

    companion object {
        private const val TAG = "SecurePrefs"
        private const val PREFS_FILE = "liberty_shield_secure_prefs"

        // Preference keys
        private const val KEY_API_KEY = "api_key"
        private const val KEY_DEVICE_ID = "device_id"
        private const val KEY_WHITELIST = "whitelist"
        private const val KEY_NOTIFICATIONS_ENABLED = "notifications_enabled"

        // Default system packages whitelisted from alerting
        val DEFAULT_WHITELIST = setOf(
            "com.android.phone",
            "com.google.android.dialer",
            "com.android.server.telecom",
            "com.samsung.android.incallui",
            "com.google.android.googlequicksearchbox",
            "com.android.systemui",
            "com.libertyshield.android"
        )
    }

    private val prefs: SharedPreferences by lazy {
        try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .setRequestStrongBoxBacked(false) // StrongBox can fail on some devices
                .build()

            EncryptedSharedPreferences.create(
                context,
                PREFS_FILE,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: Exception) {
            Log.e(TAG, "EncryptedSharedPreferences init failed — falling back to plaintext. DO NOT ship in production.", e)
            // Last-resort fallback — this path should never be reached in production
            context.getSharedPreferences("${PREFS_FILE}_fallback", Context.MODE_PRIVATE)
        }
    }

    // ===== API KEY =====

    /**
     * Returns the stored API key, falling back to BuildConfig value if not set.
     */
    fun getApiKey(): String {
        return prefs.getString(KEY_API_KEY, null)
            ?: BuildConfig.SENSOR_API_KEY.takeIf { it.isNotEmpty() }
            ?: ""
    }

    fun setApiKey(key: String) {
        prefs.edit().putString(KEY_API_KEY, key).apply()
    }

    // ===== DEVICE ID =====

    /**
     * Returns a stable random UUID for this device installation.
     * Generated on first call and persisted in encrypted prefs.
     * Reset on app uninstall/reinstall.
     */
    fun getDeviceId(): String {
        val existing = prefs.getString(KEY_DEVICE_ID, null)
        if (!existing.isNullOrEmpty()) return existing

        val newId = UUID.randomUUID().toString()
        prefs.edit().putString(KEY_DEVICE_ID, newId).apply()
        Log.i(TAG, "Generated new device ID: $newId")
        return newId
    }

    // ===== WHITELIST =====

    /**
     * Returns the set of whitelisted package names.
     * Falls back to DEFAULT_WHITELIST if nothing stored.
     */
    fun getWhitelist(): Set<String> {
        return prefs.getStringSet(KEY_WHITELIST, null) ?: DEFAULT_WHITELIST
    }

    fun setWhitelist(packages: Set<String>) {
        prefs.edit().putStringSet(KEY_WHITELIST, packages).apply()
    }

    fun addToWhitelist(packageName: String) {
        val current = getWhitelist().toMutableSet()
        current.add(packageName)
        setWhitelist(current)
    }

    fun removeFromWhitelist(packageName: String) {
        val current = getWhitelist().toMutableSet()
        current.remove(packageName)
        setWhitelist(current)
    }

    // ===== NOTIFICATIONS =====

    fun isNotificationsEnabled(): Boolean {
        return prefs.getBoolean(KEY_NOTIFICATIONS_ENABLED, true)
    }

    fun setNotificationsEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_NOTIFICATIONS_ENABLED, enabled).apply()
    }
}
