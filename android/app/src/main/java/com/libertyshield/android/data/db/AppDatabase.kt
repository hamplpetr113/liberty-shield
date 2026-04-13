/*
 * Threat model: Database encryption layer.
 * Uses SQLCipher with key derived from Android Keystore.
 * Key never leaves secure hardware on supported devices.
 *
 * Risk: SQLCipher key storage → key encrypted with Keystore alias "ls_db_key"
 * Risk: Database file access → file-based encryption + SQLCipher
 * Risk: Passphrase in memory → zeroed after use (best-effort on JVM)
 */
package com.libertyshield.android.data.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import net.sqlcipher.database.SQLiteDatabase
import net.sqlcipher.database.SupportFactory

@Database(
    entities = [SensorEventEntity::class],
    version = 1,
    exportSchema = false
)
abstract class AppDatabase : RoomDatabase() {

    abstract fun sensorEventDao(): SensorEventDao

    companion object {

        /**
         * Creates the encrypted Room database using the provided SQLCipher passphrase.
         *
         * The passphrase should be generated from the Android Keystore and stored
         * encrypted in EncryptedSharedPreferences. See DatabaseModule for key derivation.
         *
         * @param context Application context
         * @param passphrase SQLCipher passphrase bytes — caller is responsible for zeroing
         *                   this array after the database is opened.
         */
        fun create(context: Context, passphrase: ByteArray): AppDatabase {
            // loadLibs is idempotent — calling it here as a safety net for any code path
            // that reaches create() without going through LibertyShieldApp.onCreate().
            SQLiteDatabase.loadLibs(context)
            val factory = SupportFactory(passphrase)
            return Room.databaseBuilder(
                context.applicationContext,
                AppDatabase::class.java,
                "liberty_shield.db"
            )
                .openHelperFactory(factory)
                .fallbackToDestructiveMigration()
                .build()
        }
    }
}
