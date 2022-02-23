package com.pax.jc.androidkeystore

import android.text.TextUtils

/**
 * @author JQChen.
 * @date on 1/18/2022.
 */
class MainRepository(val dataSource: MainDataSource) {

    fun generateKey(
        algorithm: String,
        blockMode: String,
        padding: String,
        keySize: Int,
        authRequired: Boolean
    ): Result<Boolean, String> {
        if (TextUtils.isEmpty(algorithm)) {
            return Result.Error("Invalid algorithm!")
        }
        if (TextUtils.isEmpty(blockMode)) {
            return Result.Error("Invalid blockMode!")
        }
        if (TextUtils.isEmpty(padding)) {
            return Result.Error("Invalid padding!")
        }
        return dataSource.generateKey(algorithm, blockMode, padding, keySize, authRequired)
    }

    fun deleteKey(
        algorithm: String,
        blockMode: String,
        padding: String,
        keySize: Int
    ): Result<Boolean, String> {
        return dataSource.deleteKey(algorithm, blockMode, padding, keySize)
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
        return dataSource.encryptOrDecrypt(
            algorithm,
            blockMode,
            padding,
            keySize,
            opmode,
            byteArray,
            authRequired
        )
    }


}