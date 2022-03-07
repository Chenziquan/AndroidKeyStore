package com.jc.androidkeystore

import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.ConfirmationCallback
import android.security.ConfirmationPrompt
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.core.content.ContextCompat
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.util.concurrent.Executor
import javax.crypto.Cipher
import kotlin.random.Random

/**
 * @author JQChen.
 * @date on 11/24/2021.
 */
class KeyStoreProxy private constructor() {
    private val keyAlias = "RSATest"
    private val keyPurpose = KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT
    private val keySize = 2048
    private lateinit var context: Context

    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var encryptData: ByteArray

    companion object {
        val BIOMETRIC_SUCCESS = 0
        val BIOMETRIC_ERROR_NO_HARDWARE = 1
        val BIOMETRIC_ERROR_HW_UNAVAILABLE = 2
        val BIOMETRIC_ERROR_NONE_ENROLLED = 3
        val BIOMETRIC_ERROR_UNKNOWN = 4
        val instance: KeyStoreProxy by lazy(mode = LazyThreadSafetyMode.SYNCHRONIZED) { KeyStoreProxy() }
    }

    private lateinit var keyStoreHelper: KeyStoreHelper
    fun init(context: Context) {
        this.context = context
        keyStoreHelper = KeyStoreHelper.getInstance(context)
        executor = ContextCompat.getMainExecutor(this.context)
    }

    fun isKeyStoreBacked(alias: String): Boolean {
        return keyStoreHelper.isKeyStoreBacked(alias)
    }

    fun isDeviceSecure(): Boolean {
        val keyguardManager: KeyguardManager =
            this.context.getSystemService(KeyguardManager::class.java)
        return keyguardManager.isDeviceSecure
    }

    fun canAuthenticate(): Int {
        val biometricManager = BiometricManager.from(this.context)
        return when (biometricManager.canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)) {
            BiometricManager.BIOMETRIC_SUCCESS -> BIOMETRIC_SUCCESS
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BIOMETRIC_ERROR_NO_HARDWARE
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> BIOMETRIC_ERROR_HW_UNAVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BIOMETRIC_ERROR_NONE_ENROLLED
            else -> BIOMETRIC_ERROR_UNKNOWN
        }
    }

    val isStrongBox: Boolean get() = keyStoreHelper.isStrongBox

    fun generateKey(algorithm: String?, spec: KeyGenParameterSpec): Boolean {
        return keyStoreHelper.generateKey(algorithm, spec)
    }

    fun deleteKey(alias: String): Boolean {
        return keyStoreHelper.deleteKey(alias)
    }

    @RequiresApi(Build.VERSION_CODES.R)
    fun generateRSAKey(): Boolean {
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(keyAlias, keyPurpose)
            .setKeySize(keySize)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            .setUserAuthenticationRequired(true)
            .setRandomizedEncryptionRequired(false)
            .setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG
            )
            .build()
        return keyStoreHelper.generateKeyPair(KeyProperties.KEY_ALGORITHM_RSA, keyGenParameterSpec)
    }

    fun encryptOrDecrypt(
        alias: String?, algorithm: String, blockMode: String, padding: String,
        opmode: Int, data: ByteArray?
    ): ByteArray {
        return keyStoreHelper.crypt(alias, algorithm, blockMode, padding, opmode, null, data)
    }


    fun encryptOrDecrypt(
        alias: String?, blockMode: String, padding: String, option: Int,
        opmode: Int, data: ByteArray
    ): ByteArray {
        return keyStoreHelper.crypt(alias, option, opmode, blockMode, padding, data)
    }

    @RequiresApi(Build.VERSION_CODES.R)
    fun encryptAndDecryptData(): Boolean {
        generateRSAKey()
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
        return Cipher.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA + "/"
                    + KeyProperties.BLOCK_MODE_ECB + "/"
                    + KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
        )
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun decryptRSA() {
        // Exceptions are unhandled within this snippet.
        val cipher = getCipher()
        val secretKey = getSecretKey()
        cipher.init(Cipher.DECRYPT_MODE, secretKey)
        val signature = Signature.getInstance("SHA256withECDSA")
        biometricPrompt = BiometricPrompt.Builder(this.context)
            .setTitle("Biometric decrypt for my app")
            .setSubtitle("Decrypt in using your biometric credential")
            .setConfirmationRequired(false)
            .setNegativeButton("Use account password", executor, { _, _ -> println("onCanCel") })
            /*.setAllowedAuthenticators(
                android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL
                        or android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG
            )*/
            .build()
        biometricPrompt.authenticate(
            BiometricPrompt.CryptoObject(signature),
            CancellationSignal(),
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(
                    errorCode: Int,
                    errString: CharSequence
                ) {
                    super.onAuthenticationError(errorCode, errString)
                    println("onAuthenticationError,$errorCode, $errString")
                }

                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    super.onAuthenticationSucceeded(result)
                    /*val cipher = getCipher()
                    val secretKey = getSecretKey()
                    cipher.init(Cipher.DECRYPT_MODE, secretKey)
                    val outData = cipher.doFinal(encryptData)*/
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

    @RequiresApi(Build.VERSION_CODES.P)
    class MyConfirmationCallback : ConfirmationCallback() {
        override fun onConfirmed(dataThatWasConfirmed: ByteArray) {
            super.onConfirmed(dataThatWasConfirmed)
            // Sign dataThatWasConfirmed using your generated signing key.
            // By completing this process, you generate a "signed statement".
        }

        override fun onDismissed() {
            super.onDismissed()
            // Handle case where user declined the prompt in the
            // confirmation dialog.
        }

        override fun onCanceled() {
            super.onCanceled()
            // Handle case where your app closed the dialog before the user
            // could respond to the prompt.
        }

        override fun onError(e: Throwable?) {
            super.onError(e)
            // Handle the exception that the callback captured.
        }
    }

    // This data structure varies by app type. This is just an example.
    data class ConfirmationPromptData(
        val sender: String,
        val receiver: String, val amount: String
    )

    @RequiresApi(Build.VERSION_CODES.P)
    fun confirmPrompt() {
        val myExtraData: ByteArray = byteArrayOf()
        val myDialogData = ConfirmationPromptData("Ashlyn", "Jordan", "$500")
        val threadReceivingCallback = Executor { runnable -> runnable.run() }

        val callback = MyConfirmationCallback()
        val dialog = ConfirmationPrompt.Builder(context)
            .setPromptText("${myDialogData.sender}, send ${myDialogData.amount} to ${myDialogData.receiver}?")
            .setExtraData(myExtraData)
            .build()
        dialog.presentPrompt(threadReceivingCallback, callback)
    }

    fun generateSignKey(): Boolean {
        val keyAlias = "RSASign"
        val keyPurpose = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(keyAlias, keyPurpose)
            .setKeySize(keySize)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            .setUserAuthenticationRequired(true)
            .setRandomizedEncryptionRequired(false)
            .build()
        return keyStoreHelper.generateKeyPair(KeyProperties.KEY_ALGORITHM_RSA, keyGenParameterSpec)
    }

    @RequiresApi(Build.VERSION_CODES.P)
    fun protectConfirmPrompt() {
        generateSignKey()
        confirmPrompt()
    }


}