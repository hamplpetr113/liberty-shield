/*
 * Threat model: Network dependency injection module.
 * Provides singleton-scoped OkHttpClient, Retrofit, and ApiService instances.
 *
 * Risk: Multiple OkHttpClient instances → connection pool exhaustion.
 * Mitigation: @Singleton scope ensures exactly one instance per app lifecycle.
 *
 * Risk: Cert pin misconfiguration → app unusable until update.
 * Mitigation: BuildConfig.CERT_PIN is build-time constant; update via app release.
 */
package com.libertyshield.android.di

import com.libertyshield.android.BuildConfig
import com.libertyshield.android.network.ApiClient
import com.libertyshield.android.network.ApiService
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import okhttp3.OkHttpClient
import retrofit2.Retrofit
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {

    /**
     * Provides the OkHttpClient with certificate pinning, timeouts, and logging.
     * Certificate pinning is enforced against liberty-apps.com using the SHA-256
     * SPKI hash from BuildConfig.CERT_PIN.
     */
    @Provides
    @Singleton
    fun provideOkHttpClient(): OkHttpClient {
        return ApiClient.buildOkHttpClient()
    }

    /**
     * Provides the Retrofit instance backed by the pinned OkHttpClient.
     * Base URL is BuildConfig.API_BASE_URL = "https://liberty-apps.com".
     */
    @Provides
    @Singleton
    fun provideRetrofit(okHttpClient: OkHttpClient): Retrofit {
        return ApiClient.buildRetrofit(okHttpClient)
    }

    /**
     * Provides the ApiService interface implementation created by Retrofit.
     */
    @Provides
    @Singleton
    fun provideApiService(retrofit: Retrofit): ApiService {
        return retrofit.create(ApiService::class.java)
    }
}
