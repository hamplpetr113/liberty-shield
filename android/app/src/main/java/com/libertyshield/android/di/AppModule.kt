/*
 * Threat model: Application-level dependency injection module.
 * Provides system services and core engine components.
 *
 * Risk: AppOpsManager not available (API < 19) → min SDK is 26, not a concern.
 * Risk: ActivityManager runningProcesses deprecated in API 26+ → used for best-effort
 *       background detection only; errors are caught in SensorDetector.
 * Risk: SensorDetector and MisdirectionEngine are stateful → @Singleton scope
 *       ensures single shared instance managed by Hilt's component lifecycle.
 */
package com.libertyshield.android.di

import android.app.ActivityManager
import android.app.AppOpsManager
import android.content.Context
import android.content.pm.PackageManager
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    /**
     * Provides the AppOpsManager system service.
     * Used by SensorDetector to query per-package AppOps state.
     */
    @Provides
    @Singleton
    fun provideAppOpsManager(@ApplicationContext context: Context): AppOpsManager {
        return context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
    }

    /**
     * Provides the ActivityManager system service.
     * Used by SensorDetector to determine foreground/background state of packages.
     */
    @Provides
    @Singleton
    fun provideActivityManager(@ApplicationContext context: Context): ActivityManager {
        return context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
    }

    /**
     * Provides the PackageManager.
     * Used by SensorDetector to enumerate installed packages and their UIDs.
     */
    @Provides
    @Singleton
    fun providePackageManager(@ApplicationContext context: Context): PackageManager {
        return context.packageManager
    }

    // NOTE: SensorDetector and MisdirectionEngine are NOT provided here.
    // Both classes carry @Singleton + @Inject constructor, which is sufficient
    // for Hilt to construct and scope them automatically.
    // Adding a duplicate @Provides for those types causes a Dagger
    // "duplicate binding" error in Hilt 2.44+ and was removed.
}
