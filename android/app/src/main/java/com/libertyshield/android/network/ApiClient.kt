/*
 * Threat model: Network security layer.
 * Certificate pinning prevents MITM attacks even on compromised networks.
 *
 * IMPORTANT: Replace CERT_PIN in local.properties with the actual SHA-256
 * public key pin for liberty-apps.com. Obtain with:
 *   openssl s_client -connect liberty-apps.com:443 -servername liberty-apps.com \
 *     </dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
 *     | openssl dgst -sha256 -binary | base64
 *
 * Risk: Pinned cert expiry → update pin before cert renewal
 * Risk: Pin bypass via compromised CA → pinning defeats this
 * Risk: Network interception → TLS 1.2+ + pinning defeats this
 */
package com.libertyshield.android.network

import com.libertyshield.android.BuildConfig
import okhttp3.CertificatePinner
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

object ApiClient {

    private const val CONNECT_TIMEOUT_S = 30L
    private const val READ_TIMEOUT_S = 30L
    private const val WRITE_TIMEOUT_S = 30L
    private const val HOST = "liberty-apps.com"
    private const val USER_AGENT = "LibertyShield-Android/1.0"

    /**
     * Constructs the certificate pinner.
     * The pin is injected at build time from local.properties via BuildConfig.CERT_PIN.
     *
     * Pin format must be "sha256/<base64-encoded-spki-hash>".
     * Example: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
     */
    private fun buildCertificatePinner(): CertificatePinner {
        return CertificatePinner.Builder()
            .add(HOST, BuildConfig.CERT_PIN)
            .build()
    }

    /**
     * Adds "User-Agent: LibertyShield-Android/1.0" to every request.
     * Helps server distinguish app traffic from generic HTTP clients.
     */
    private val userAgentInterceptor = Interceptor { chain ->
        val request = chain.request().newBuilder()
            .header("User-Agent", USER_AGENT)
            .build()
        chain.proceed(request)
    }

    /**
     * Logging interceptor: BODY level in debug builds, NONE in release.
     * NEVER log in release — auth tokens would appear in logcat.
     */
    private fun buildLoggingInterceptor(): HttpLoggingInterceptor {
        return HttpLoggingInterceptor().apply {
            level = if (BuildConfig.DEBUG) {
                HttpLoggingInterceptor.Level.BODY
            } else {
                HttpLoggingInterceptor.Level.NONE
            }
        }
    }

    /**
     * Creates an OkHttpClient with:
     *   - Certificate pinning for liberty-apps.com
     *   - Request timeouts
     *   - User-Agent header injection
     *   - Conditional logging (debug only)
     */
    fun buildOkHttpClient(): OkHttpClient {
        return OkHttpClient.Builder()
            .certificatePinner(buildCertificatePinner())
            .connectTimeout(CONNECT_TIMEOUT_S, TimeUnit.SECONDS)
            .readTimeout(READ_TIMEOUT_S, TimeUnit.SECONDS)
            .writeTimeout(WRITE_TIMEOUT_S, TimeUnit.SECONDS)
            .addInterceptor(userAgentInterceptor)
            .addInterceptor(buildLoggingInterceptor())
            .build()
    }

    /**
     * Creates the Retrofit instance backed by the pinned OkHttpClient.
     */
    fun buildRetrofit(okHttpClient: OkHttpClient): Retrofit {
        return Retrofit.Builder()
            .baseUrl(BuildConfig.API_BASE_URL + "/")
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
    }

    /**
     * Convenience factory — creates both OkHttpClient and Retrofit in one call.
     * Used in NetworkModule when not injecting a pre-built client.
     */
    fun create(): ApiService {
        val client = buildOkHttpClient()
        val retrofit = buildRetrofit(client)
        return retrofit.create(ApiService::class.java)
    }
}
