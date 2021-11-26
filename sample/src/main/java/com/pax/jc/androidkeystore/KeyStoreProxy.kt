package com.pax.jc.androidkeystore

import android.content.Context
import android.content.DialogInterface
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import java.security.KeyStore
import java.security.PrivateKey
import java.util.concurrent.Executor
import javax.crypto.Cipher
import kotlin.random.Random

/**
 * @author JQChen.
 * @date on 11/24/2021.
 */
class KeyStoreProxy {
    private val keyAlias = "RSATest"
    private val keyPurpose = KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT
    private val keySize = 2048
    private lateinit var context: Context

    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var encryptData: ByteArray

    private lateinit var keyStoreHelper: KeyStoreHelper
    fun init(context: Context) {
        this.context = context
        keyStoreHelper = KeyStoreHelper.getInstance(context)
        executor = ContextCompat.getMainExecutor(this.context)
    }

    fun generateRSAKey(): Boolean {
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(keyAlias, keyPurpose)
                .setKeySize(keySize)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .setUserAuthenticationRequired(true)
                .setRandomizedEncryptionRequired(false)
                .build();
        return keyStoreHelper.generateKeyPair(KeyProperties.KEY_ALGORITHM_RSA, keyGenParameterSpec)
    }

    @RequiresApi(Build.VERSION_CODES.P)
    fun encryptAndDecryptData(): Boolean {
        val data = ByteArray(size = 32)
        Random.Default.nextBytes(data)
        val srcData = String(data, Charsets.UTF_8)
        println(srcData)
        val encrypt = keyStoreHelper.encryptRSA(keyAlias, data)
        encryptData = encrypt
        println(String(encrypt, Charsets.UTF_8))
        decryptRSA()
        return true
        /*val decrypt = keyStoreHelper.decryptRSA(keyAlias, encrypt)
        val outData = String(decrypt, Charsets.UTF_8)
        println(outData)
        return srcData == outData*/
    }

    fun deleteKey(): Boolean {
        return keyStoreHelper.deleteKey(keyAlias)
    }

    private fun getSecretKey(): PrivateKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")

        // Before the keystore can be accessed, it must be loaded.
        keyStore.load(null)
        return keyStore.getKey(keyAlias, null) as PrivateKey
    }

    private fun getCipher(): Cipher {
        return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_RSA + "/"
                + KeyProperties.BLOCK_MODE_ECB + "/"
                + KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
    }

    @RequiresApi(Build.VERSION_CODES.P)
    private fun decryptRSA() {
        // Exceptions are unhandled within this snippet.
        val cipher = getCipher()
        val secretKey = getSecretKey()
        cipher.init(Cipher.DECRYPT_MODE, secretKey)
        biometricPrompt = BiometricPrompt.Builder(this.context)
                .setTitle("Biometric decrypt for my app")
                .setSubtitle("Decrypt in using your biometric credential")
                .setNegativeButton("Use account password", executor, { _, _ -> println("onCanCel") })
                .build()
        biometricPrompt.authenticate(BiometricPrompt.CryptoObject(cipher), CancellationSignal(), executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int,
                                               errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                println("onAuthenticationError,$errorCode, $errString")
            }

            override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                val outData = result.cryptoObject.cipher?.doFinal(encryptData)
                if (outData == null) {
                    println("outData is null")
                } else {
                    println(String(outData, Charsets.UTF_8))
                }
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                println("onAuthenticationFailed")
            }
        })
    }


}