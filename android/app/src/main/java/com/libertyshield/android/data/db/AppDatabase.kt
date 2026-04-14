/*
 * Threat model: Database encryption layer.
 * Uses SQLCipher with key derived from Android Keystore.
 * Key never leaves secure hardware on supported devices.
 *
 * Risk: SQLCipher key storage → key encrypted with Keystore alias "ls_db_key"
 * Risk: Database file access → file-based encryption + SQLCipher
 * Risk: Passphrase in memory → zeroed by SupportFactory after copy (best-effort on JVM)
 * Risk: Passphrase mismatch on reinstall → DatabaseModule.createDatabase() wipes + retries
 */
package com.libertyshield.android.data.db

import androidx.room.Database
import androidx.room.RoomDatabase

@Database(
    entities = [SensorEventEntity::class],
    version = 1,
    exportSchema = false
)
abstract class AppDatabase : RoomDatabase() {

    abstract fun sensorEventDao(): SensorEventDao
}
