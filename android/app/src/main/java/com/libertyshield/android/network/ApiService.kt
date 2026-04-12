/*
 * Threat model: Network interface definition.
 * All calls go over HTTPS with certificate pinning (enforced in ApiClient).
 *
 * Risk: Replay attacks → server should validate ts field for freshness
 * Risk: Auth token exposure in logs → logging interceptor disabled in release
 */
package com.libertyshield.android.network

import com.google.gson.annotations.SerializedName
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.Header
import retrofit2.http.POST

interface ApiService {

    /**
     * Reports a single sensor access event to the Liberty Shield backend.
     *
     * @param auth  Bearer token — "Bearer <api_key>"
     * @param payload  The event payload with all sensor access details.
     */
    @POST("api/sensors/event")
    suspend fun reportEvent(
        @Header("Authorization") auth: String,
        @Body payload: SensorEventPayload
    ): Response<Unit>

    /**
     * Health check endpoint — used by SyncWorker to verify connectivity
     * before batching events.
     */
    @POST("api/health")
    suspend fun healthCheck(): Response<Unit>
}

/**
 * Network DTO — matches the server-side schema.
 * All field names use snake_case via @SerializedName.
 *
 * This class is kept in proguard-rules.pro to prevent obfuscation
 * from breaking Gson serialization.
 */
data class SensorEventPayload(
    @SerializedName("device_id")
    val deviceId: String,

    @SerializedName("sensor")
    val sensor: String,           // "microphone" or "camera"

    @SerializedName("app_package")
    val appPackage: String,

    @SerializedName("app_label")
    val appLabel: String,

    @SerializedName("action")
    val action: String,           // "start" or "stop"

    @SerializedName("risk_score")
    val riskScore: Int,

    @SerializedName("misdirection_active")
    val misdirectionActive: Boolean,

    @SerializedName("ts")
    val ts: Long                  // Unix epoch milliseconds
)
