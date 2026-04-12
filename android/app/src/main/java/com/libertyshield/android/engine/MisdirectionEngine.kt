/*
 * Threat model: FVC (Forward-Verified Chain) misdirection layer.
 * Mirror Labyrinth concept: attacker believes they are recording,
 * but receives contaminated or empty data.
 *
 * Microphone misdirection:
 *   - Plays white noise via AudioTrack through device speaker at low volume
 *   - Contaminates any concurrent microphone recording
 *   - Limitation: ineffective with earphones/headphones plugged in
 *   - Limitation: Android 10+ allows concurrent recording; white noise
 *     through speaker is the only available contamination vector without root.
 *
 * Camera misdirection:
 *   - Cannot inject fake frames without root/system privileges
 *   - Activates flash/torch to overexpose camera capture (soft mitigation)
 *   - Documents this limitation clearly
 *
 * Risk: Misdirection reveals our presence to a sophisticated attacker
 * Mitigation: White noise is plausibly deniable (room noise)
 */
package com.libertyshield.android.engine

import android.content.Context
import android.hardware.camera2.CameraManager
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioTrack
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.roundToInt
import kotlin.random.Random

@Singleton
class MisdirectionEngine @Inject constructor() {

    companion object {
        private const val TAG = "MisdirectionEngine"
        private const val SAMPLE_RATE = 44100
        private const val NOISE_AMPLITUDE = 0.20f  // 20% amplitude — plausibly deniable room noise
    }

    private val engineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var micJob: Job? = null
    private var audioTrack: AudioTrack? = null
    private var torchCameraId: String? = null

    @Volatile var isMicMisdirectionActive: Boolean = false
        private set

    @Volatile var isCamMisdirectionActive: Boolean = false
        private set

    // ===== MICROPHONE MISDIRECTION =====

    /**
     * Starts playing continuous white noise through the device speaker.
     * The speaker output bleeds into any microphone recording happening concurrently.
     * Uses AudioTrack in streaming mode for minimal memory usage.
     */
    fun startMicrophoneMisdirection() {
        if (isMicMisdirectionActive) return

        val bufferSize = AudioTrack.getMinBufferSize(
            SAMPLE_RATE,
            AudioFormat.CHANNEL_OUT_STEREO,
            AudioFormat.ENCODING_PCM_16BIT
        ).let { min ->
            // Use 4x the minimum to avoid underruns
            if (min == AudioTrack.ERROR_BAD_VALUE || min == AudioTrack.ERROR) {
                SAMPLE_RATE / 4  // fallback: ~250ms buffer
            } else {
                min * 4
            }
        }

        val track = AudioTrack(
            AudioManager.STREAM_MUSIC,
            SAMPLE_RATE,
            AudioFormat.CHANNEL_OUT_STEREO,
            AudioFormat.ENCODING_PCM_16BIT,
            bufferSize,
            AudioTrack.MODE_STREAM
        )

        if (track.state != AudioTrack.STATE_INITIALIZED) {
            Log.e(TAG, "AudioTrack failed to initialize — misdirection not started")
            track.release()
            return
        }

        audioTrack = track
        isMicMisdirectionActive = true
        track.play()

        micJob = engineScope.launch {
            Log.i(TAG, "Microphone misdirection STARTED — streaming white noise at ${(NOISE_AMPLITUDE * 100).roundToInt()}% amplitude")
            try {
                val noiseBuffer = generateWhiteNoise(bufferSize / 2) // divide by 2: ShortArray vs ByteArray size
                while (isActive && isMicMisdirectionActive) {
                    val written = track.write(noiseBuffer, 0, noiseBuffer.size)
                    if (written < 0) {
                        Log.w(TAG, "AudioTrack write error: $written")
                        break
                    }
                    // Regenerate noise periodically to prevent pattern detection
                    val freshNoise = generateWhiteNoise(bufferSize / 2)
                    System.arraycopy(freshNoise, 0, noiseBuffer, 0, noiseBuffer.size)
                }
            } catch (e: Exception) {
                Log.e(TAG, "White noise streaming error: ${e.message}", e)
            } finally {
                isMicMisdirectionActive = false
                Log.i(TAG, "Microphone misdirection STOPPED")
            }
        }
    }

    /**
     * Stops white noise playback and releases AudioTrack resources.
     */
    fun stopMicrophoneMisdirection() {
        if (!isMicMisdirectionActive) return
        isMicMisdirectionActive = false
        micJob?.cancel()
        micJob = null
        try {
            audioTrack?.stop()
            audioTrack?.release()
        } catch (e: Exception) {
            Log.w(TAG, "Error stopping AudioTrack: ${e.message}")
        } finally {
            audioTrack = null
            Log.i(TAG, "Microphone misdirection deactivated")
        }
    }

    // ===== CAMERA MISDIRECTION =====

    /**
     * Activates the device torch/flash to overexpose concurrent camera recordings.
     *
     * Limitation: This only works on devices with a rear torch.
     * Limitation: Front-camera recordings will not be affected by rear torch.
     * Limitation: Apps using Camera2 API can detect torch state — not fully covert.
     *
     * Despite limitations, this is the only available camera misdirection
     * vector without root or system privileges on stock Android.
     */
    fun startCameraMisdirection(context: Context) {
        if (isCamMisdirectionActive) return

        try {
            val cameraManager = context.getSystemService(Context.CAMERA_SERVICE) as CameraManager
            val cameraId = findTorchCameraId(cameraManager)

            if (cameraId == null) {
                Log.w(TAG, "No torch-capable camera found — camera misdirection unavailable")
                return
            }

            cameraManager.setTorchMode(cameraId, true)
            torchCameraId = cameraId
            isCamMisdirectionActive = true
            Log.i(TAG, "Camera misdirection STARTED — torch activated on camera $cameraId")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to activate torch: ${e.message}", e)
        }
    }

    /**
     * Deactivates torch and clears camera misdirection state.
     */
    fun stopCameraMisdirection(context: Context) {
        if (!isCamMisdirectionActive) return

        try {
            val cameraId = torchCameraId ?: return
            val cameraManager = context.getSystemService(Context.CAMERA_SERVICE) as CameraManager
            cameraManager.setTorchMode(cameraId, false)
            Log.i(TAG, "Camera misdirection STOPPED — torch deactivated")
        } catch (e: Exception) {
            Log.w(TAG, "Error deactivating torch: ${e.message}")
        } finally {
            isCamMisdirectionActive = false
            torchCameraId = null
        }
    }

    // ===== HELPERS =====

    /**
     * Generates a buffer of white noise samples scaled to [NOISE_AMPLITUDE].
     *
     * Output is a ShortArray (PCM 16-bit) where each sample is a random value
     * in range [-(32767 * amplitude), +(32767 * amplitude)].
     *
     * Stereo interleaved: [L0, R0, L1, R1, ...]
     */
    fun generateWhiteNoise(bufferSize: Int): ShortArray {
        val max = (Short.MAX_VALUE * NOISE_AMPLITUDE).toInt()
        return ShortArray(bufferSize) {
            (Random.nextInt(-max, max)).toShort()
        }
    }

    private fun findTorchCameraId(cameraManager: CameraManager): String? {
        return try {
            cameraManager.cameraIdList.firstOrNull { id ->
                val chars = cameraManager.getCameraCharacteristics(id)
                val available = chars.get(
                    android.hardware.camera2.CameraCharacteristics.FLASH_INFO_AVAILABLE
                )
                available == true
            }
        } catch (e: Exception) {
            Log.w(TAG, "Could not enumerate cameras: ${e.message}")
            null
        }
    }
}
