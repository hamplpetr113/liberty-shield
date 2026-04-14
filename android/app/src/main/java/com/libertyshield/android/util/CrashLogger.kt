/*
 * Crash instrumentation layer.
 *
 * Saves the last uncaught exception to PLAIN (unencrypted) SharedPreferences so it
 * survives a process death and is readable on the very next cold launch — before
 * EncryptedSharedPreferences, SQLCipher, or Hilt have been initialised.
 *
 * Design constraints:
 *   - Zero dependencies on any other app class.
 *   - Plain SharedPreferences only — crypto stack may itself be the crash source.
 *   - commit() not apply() — the process may be killed immediately after the handler.
 *   - Stack trace truncated to MAX_STACK_CHARS to stay inside Binder IPC limits.
 */
package com.libertyshield.android.util

import android.content.Context
import android.util.Log

object CrashLogger {

    private const val TAG = "CrashLogger"
    private const val PREFS_FILE      = "ls_crash_log"       // intentionally unencrypted
    private const val KEY_CLASS       = "crash_class"
    private const val KEY_MESSAGE     = "crash_message"
    private const val KEY_STACK       = "crash_stack"
    private const val KEY_THREAD      = "crash_thread"
    private const val KEY_TIMESTAMP   = "crash_ts"
    private const val MAX_STACK_CHARS = 3000

    // ── Public API ──────────────────────────────────────────────────────────

    data class CrashInfo(
        val exceptionClass: String,
        val message: String,
        val stacktrace: String,
        val threadName: String,
        val timestamp: Long
    ) {
        /** One-line summary suitable for a log tag or toast. */
        val summary: String get() = "$exceptionClass: $message"
    }

    /**
     * Install a global Thread.UncaughtExceptionHandler that persists any fatal
     * Throwable before delegating to the platform default handler (which kills the process).
     *
     * Must be called as early as possible — ideally the very first line of
     * Application.onCreate() — so that Hilt/Room/Compose crashes are captured.
     */
    fun install(context: Context) {
        val appContext = context.applicationContext
        val previous   = Thread.getDefaultUncaughtExceptionHandler()

        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            try {
                Log.e(TAG, "UNCAUGHT EXCEPTION on thread '${thread.name}': ${throwable.message}", throwable)
                saveCrash(appContext, throwable, thread.name)
            } catch (e: Throwable) {
                // Never let the instrumentation itself mask the real crash.
                Log.e(TAG, "CrashLogger.saveCrash itself threw: ${e.message}")
            } finally {
                previous?.uncaughtException(thread, throwable)
            }
        }

        Log.i(TAG, "Global uncaught-exception handler installed (previous=$previous)")
    }

    /**
     * Save a Throwable explicitly (e.g. caught in a try/catch but still fatal-ish).
     */
    fun saveCrash(context: Context, throwable: Throwable, threadName: String = Thread.currentThread().name) {
        try {
            val stack = throwable.stackTraceToString().take(MAX_STACK_CHARS)
            context.applicationContext
                .getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)
                .edit()
                .putString(KEY_CLASS,     throwable.javaClass.name)
                .putString(KEY_MESSAGE,   throwable.message ?: "(no message)")
                .putString(KEY_STACK,     stack)
                .putString(KEY_THREAD,    threadName)
                .putLong  (KEY_TIMESTAMP, System.currentTimeMillis())
                .commit()   // commit() — process may die before apply() flushes
            Log.i(TAG, "Crash persisted: ${throwable.javaClass.simpleName}: ${throwable.message}")
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to persist crash: ${e.message}")
        }
    }

    /**
     * Read the last persisted crash. Returns null if no crash has been recorded.
     * Safe to call from any thread, including the main thread on cold launch.
     */
    fun getLastCrash(context: Context): CrashInfo? {
        return try {
            val prefs = context.applicationContext
                .getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)
            val ts = prefs.getLong(KEY_TIMESTAMP, 0L)
            if (ts == 0L) return null
            CrashInfo(
                exceptionClass = prefs.getString(KEY_CLASS,   "Unknown") ?: "Unknown",
                message        = prefs.getString(KEY_MESSAGE, "")        ?: "",
                stacktrace     = prefs.getString(KEY_STACK,   "")        ?: "",
                threadName     = prefs.getString(KEY_THREAD,  "unknown") ?: "unknown",
                timestamp      = ts
            )
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to read crash log: ${e.message}")
            null
        }
    }

    /** Remove the persisted crash record (e.g. after the user acknowledges it). */
    fun clear(context: Context) {
        try {
            context.applicationContext
                .getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)
                .edit().clear().apply()
            Log.i(TAG, "Crash log cleared")
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to clear crash log: ${e.message}")
        }
    }
}
