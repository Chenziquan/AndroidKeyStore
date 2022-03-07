package com.jc.androidkeystore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.jc.androidkeystore.KeyStoreProxy.Companion.BIOMETRIC_SUCCESS
import com.jc.androidkeystore.KeyStoreProxy.Companion.BIOMETRIC_ERROR_NO_HARDWARE
import com.jc.androidkeystore.KeyStoreProxy.Companion.BIOMETRIC_ERROR_HW_UNAVAILABLE
import com.jc.androidkeystore.KeyStoreProxy.Companion.BIOMETRIC_ERROR_NONE_ENROLLED
import com.jc.androidkeystore.KeyStoreProxy.Companion.BIOMETRIC_ERROR_UNKNOWN
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * @author JQChen.
 * @date on 1/18/2022.
 */
class MainDataSource {

    fun generateKey(
        algorithm: String,
        blockMode: String,
        padding: String,
        keySize: Int,
        authRequired: Boolean
    ): Result<Boolean, String> {
        return try {
            val alias = getKeyAlias(algorithm, blockMode, padding, keySize)
            val keyStoreProxy = KeyStoreProxy.instance
            if (keyStoreProxy.isKeyStoreBacked(alias)) {
                return Result.Success(false)
            }
            if (authRequired) {
                val result = isDeviceSecure()
                if (result is Result.Error) {
                    return result
                }
            }
            val keyPurpose = KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT
            val builder = KeyGenParameterSpec.Builder(alias, keyPurpose)
                .setKeySize(keySize)
                .setBlockModes(blockMode)
                .setEncryptionPaddings(padding)
                .setUserAuthenticationRequired(authRequired)
            if (blockMode.equals(KeyProperties.BLOCK_MODE_ECB)) {
                builder.setRandomizedEncryptionRequired(false)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                if (keyStoreProxy.isStrongBox) {
                    builder.setIsStrongBoxBacked(true)
                }
            }
            return if (keyStoreProxy.generateKey(algorithm, builder.build())) {
                Result.Success(true)
            } else {
                Result.Error("Generate key fail!")
            }
        } catch (e: Exception) {
            Result.Error(e.toString())
        }
    }

    fun deleteKey(
        algorithm: String,
        blockMode: String,
        padding: String,
        keySize: Int
    ): Result<Boolean, String> {
        val alias = getKeyAlias(algorithm, blockMode, padding, keySize)
        val keyStoreProxy = KeyStoreProxy.instance
        return if (keyStoreProxy.deleteKey(alias)) {
            Result.Success(true)
        } else {
            Result.Error("Delete key fail!")
        }
    }

    suspend fun encryptOrDecrypt(
        algorithm: String,
        blockMode: String,
        padding: String,
        keySize: Int,
        opmode: Int,
        byteArray: ByteArray,
        authRequired: Boolean
    ): Result<ByteArray, String> {
        return withContext(Dispatchers.IO) {
            val alias = getKeyAlias(algorithm, blockMode, padding, keySize)
            val keyStoreProxy = KeyStoreProxy.instance
            if (!keyStoreProxy.isKeyStoreBacked(alias)) {
                Result.Error("Key not exist!")
            }
            var data = byteArray
            if (blockMode == KeyProperties.BLOCK_MODE_ECB) {
                data = formatData(byteArray, 16)
            }
            if (authRequired) {
                val result = isDeviceSecure()
                if (result is Result.Error) {
                    Result.Error(result.data)
                }

            }
            if (algorithm == KeyProperties.KEY_ALGORITHM_AES) {
                // Symmetric key
                Result.Success(
                    keyStoreProxy.encryptOrDecrypt(
                        alias,
                        algorithm,
                        blockMode,
                        padding,
                        opmode,
                        data
                    )
                )
            } else {
                // asymmetric key
                Result.Success(
                    keyStoreProxy.encryptOrDecrypt(
                        alias,
                        blockMode,
                        padding,
                        opmode,
                        opmode,
                        data
                    )
                )
            }

        }

    }

    private fun formatData(data: ByteArray, format: Int): ByteArray {
        val diff = data.size % format
        if (diff != 0) {
            val formatArray = ByteArray(data.size + diff)
            System.arraycopy(data, 0, formatArray, 0, data.size)
            return formatArray
        } else {
            return data
        }
    }


    private fun getKeyAlias(
        algorithm: String,
        blockMode: String,
        padding: String,
        keySize: Int
    ): String {
        return "${algorithm}_${blockMode}_${padding}_${keySize}"
    }

    private fun isDeviceSecure(): Result<Boolean, String> {
        val keyStoreProxy = KeyStoreProxy.instance
        if (!keyStoreProxy.isDeviceSecure()) {
            return Result.Error("Device is not secure!")
        }
        val auth = keyStoreProxy.canAuthenticate()
        if (auth != BIOMETRIC_SUCCESS) {
            return when (auth) {
                BIOMETRIC_ERROR_NO_HARDWARE -> Result.Error("there is no suitable hardware")
                BIOMETRIC_ERROR_HW_UNAVAILABLE -> Result.Error("the hardware is unavailable. Try again later.")
                BIOMETRIC_ERROR_NONE_ENROLLED -> Result.Error("no biometric or device credential is enrolled.")
                BIOMETRIC_ERROR_UNKNOWN -> Result.Error("Unknown error")
                else -> Result.Error("there is no suitable hardware")
            }
        }
        return Result.Success(true)
    }

}