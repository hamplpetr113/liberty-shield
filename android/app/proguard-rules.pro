# ============================================================
# Liberty Shield ProGuard Rules
# Threat model: Obfuscation layer — makes reverse engineering harder.
# Risk: Over-aggressive shrinking breaks runtime reflection.
# Mitigation: Explicit keep rules for all reflection-dependent libs.
# ============================================================

# --- Hilt / Dagger ---
-keep class dagger.hilt.** { *; }
-keep class javax.inject.** { *; }
-keep @dagger.hilt.android.HiltAndroidApp class * { *; }
-keep @dagger.hilt.android.AndroidEntryPoint class * { *; }
-keepclasseswithmembernames class * {
    @javax.inject.Inject <fields>;
    @javax.inject.Inject <init>(...);
}

# --- Room ---
-keep class androidx.room.** { *; }
-keep @androidx.room.Entity class * { *; }
-keep @androidx.room.Dao class * { *; }
-keep @androidx.room.Database class * { *; }
-keepclassmembers class * extends androidx.room.RoomDatabase {
    abstract *;
}

# --- SQLCipher ---
-keep class net.sqlcipher.** { *; }
-keep class net.sqlcipher.database.** { *; }

# --- Retrofit + OkHttp ---
-keep class retrofit2.** { *; }
-keep interface retrofit2.** { *; }
-keep class okhttp3.** { *; }
-keep interface okhttp3.** { *; }
-keep class okio.** { *; }
-dontwarn retrofit2.**
-dontwarn okhttp3.**
-dontwarn okio.**

# --- Gson ---
-keep class com.google.gson.** { *; }
-keep class * implements com.google.gson.TypeAdapterFactory { *; }
-keep class * implements com.google.gson.JsonSerializer { *; }
-keep class * implements com.google.gson.JsonDeserializer { *; }
-keepclassmembers,allowobfuscation class * {
    @com.google.gson.annotations.SerializedName <fields>;
}

# --- Network models (sent over the wire) ---
-keep class com.libertyshield.android.network.SensorEventPayload { *; }

# --- WorkManager ---
-keep class androidx.work.** { *; }
-keep class * extends androidx.work.Worker { *; }
-keep class * extends androidx.work.CoroutineWorker { *; }

# --- Kotlin coroutines ---
-keep class kotlinx.coroutines.** { *; }
-dontwarn kotlinx.coroutines.**

# --- Kotlin metadata (needed for reflection) ---
-keep class kotlin.Metadata { *; }

# --- AndroidX Security (EncryptedSharedPreferences) ---
-keep class androidx.security.crypto.** { *; }

# --- Our app classes ---
-keep class com.libertyshield.android.** { *; }

# --- Suppress notes ---
-dontnote **
