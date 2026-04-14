/*
 * Non-sensitive runtime state stored in plain SharedPreferences.
 *
 * Used by components that cannot use Hilt injection (BootReceiver, WorkManager callbacks).
 * "Shield enabled" is a user preference, not a credential — plain storage is appropriate.
 *
 * Do NOT store secrets here. Secrets (API key, device ID, DB passphrase) stay in
 * SecurePrefs backed by EncryptedSharedPreferences + Android Keystore.
 */
package com.libertyshield.android.data

import android.content.Context
import android.content.SharedPreferences

object ShieldPreferences {

    private const val PREFS_NAME           = "liberty_shield_state"
    private const val KEY_SHIELD_ENABLED   = "shield_enabled"
    private const val KEY_LAST_SYNC_TIME   = "last_sync_time_ms"
    private const val KEY_LAST_SYNC_OK     = "last_sync_success"
    private const val KEY_LAST_SYNC_COUNT  = "last_sync_event_count"

    // ===== SHIELD STATE =====

    /** True if the user has activated Liberty Shield protection. */
    fun isShieldEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_SHIELD_ENABLED, false)

    fun setShieldEnabled(context: Context, enabled: Boolean) =
        prefs(context).edit().putBoolean(KEY_SHIELD_ENABLED, enabled).apply()

    // ===== SYNC TRACKING =====

    /** Epoch ms of the most recent sync attempt (0 = never). */
    fun getLastSyncTime(context: Context): Long =
        prefs(context).getLong(KEY_LAST_SYNC_TIME, 0L)

    /** True if the last sync completed without errors. */
    fun getLastSyncSuccess(context: Context): Boolean =
        prefs(context).getBoolean(KEY_LAST_SYNC_OK, false)

    /** Number of events uploaded during the last successful sync. */
    fun getLastSyncCount(context: Context): Int =
        prefs(context).getInt(KEY_LAST_SYNC_COUNT, 0)

    /**
     * Records the outcome of a sync attempt.
     * Called by SyncWorker on both success and failure paths.
     */
    fun setLastSyncResult(context: Context, success: Boolean, eventCount: Int) {
        prefs(context).edit()
            .putLong(KEY_LAST_SYNC_TIME, System.currentTimeMillis())
            .putBoolean(KEY_LAST_SYNC_OK, success)
            .putInt(KEY_LAST_SYNC_COUNT, eventCount)
            .apply()
    }

    // ===== INTERNAL =====

    private fun prefs(context: Context): SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
}
