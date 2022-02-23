package com.pax.jc.androidkeystore

import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import android.text.TextUtils
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import java.io.IOException
import java.lang.ref.WeakReference
import java.security.*
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.spec.ECGenParameterSpec
import java.security.spec.InvalidKeySpecException
import java.util.*
import java.util.concurrent.Executor
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * @author Michael.Z.
 * @date on 8/9/2021.
 */
class KeyStoreHelper private constructor(context: Context) {
    private lateinit var mKeyStore: KeyStore
    private var mContextWeakReference: WeakReference<Context>? = null
    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt

    /**
     * Save the AES key to the KeyStore.
     *
     * @param alias    alias
     * @param keyValue keyValue
     * @return true: success; false: fail.
     */
    fun saveAESKey(alias: String?, keyValue: ByteArray?): Boolean {
        if (TextUtils.isEmpty(alias)) {
            return false
        }
        return if (notFormatInputData(keyValue)) {
            false
        } else saveKeyToKeyStore(alias, KeyProperties.KEY_ALGORITHM_AES, keyValue)
    }

    /**
     * Delete key from KeyStore.
     *
     * @param alias alias
     * @return true: success; false: fail.
     */
    fun deleteKey(alias: String?): Boolean {
        return if (TextUtils.isEmpty(alias)) {
            false
        } else try {
            mKeyStore.deleteEntry(alias)
            true
        } catch (exception: KeyStoreException) {
            exception.printStackTrace()
            false
        }
    }

    /**
     * Save key to the KeyStore.
     *
     * @param alias     alias
     * @param algorithm algorithm
     * @param keyValue  keyValue
     * @return true: success; fasle: fail.
     */
    private fun saveKeyToKeyStore(
        alias: String?,
        algorithm: String,
        keyValue: ByteArray?
    ): Boolean {
        if (TextUtils.isEmpty(alias)) {
            return false
        }
        if (TextUtils.isEmpty(algorithm)) {
            return false
        }
        return if (notFormatInputData(keyValue)) {
            false
        } else try {
            val secretKey: SecretKey = SecretKeySpec(keyValue, algorithm)
            val secretKeyEntry = KeyStore.SecretKeyEntry(secretKey)
            mKeyStore.setEntry(alias, secretKeyEntry, keyProtection)
            true
        } catch (exception: KeyStoreException) {
            exception.printStackTrace()
            false
        }
    }

    /**
     * Get KeyProtection.
     *
     * @return KeyProtection
     */
    private val keyProtection: KeyProtection
        get() = KeyProtection.Builder(
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_ECB, KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(
                KeyProperties.ENCRYPTION_PADDING_NONE,
                KeyProperties.ENCRYPTION_PADDING_PKCS7
            )
            .setRandomizedEncryptionRequired(false)
            .setUserAuthenticationRequired(false)
            .build()

    /**
     * Get the kcv of the key.
     *
     * @param alias alias
     * @return the kcv
     */
    fun getKCV(alias: String?): ByteArray {
        val result = ByteArray(0)
        if (isNotKeyStoreBacked(alias)) {
            return result
        }
        val data = ByteArray(16)
        val out = cryptCBC(alias, Cipher.ENCRYPT_MODE, data)
        return if (out.size < 3) {
            result
        } else {
            Arrays.copyOf(out, 3)
        }
    }

    /**
     * Generate the key.
     *
     * @param algorithm algorithm
     * @param alias     alias
     * @return true:success; false:fail.
     */
    fun generateKey(algorithm: String?, alias: String): Boolean {
        return when (algorithm) {
            KeyProperties.KEY_ALGORITHM_RSA -> generateRSA(alias)
            KeyProperties.KEY_ALGORITHM_AES -> generateAES(alias)
            KeyProperties.KEY_ALGORITHM_EC -> generateEC(alias)
            else -> false
        }
    }

    fun generateKey(algorithm: String?, spec: KeyGenParameterSpec): Boolean {
        return when (algorithm) {
            KeyProperties.KEY_ALGORITHM_RSA, KeyProperties.KEY_ALGORITHM_EC -> generateKeyPair(
                algorithm, spec
            )
            else -> generateSymmetricKey(algorithm, spec)
        }
    }

    fun generateKeyPair(algorithm: String?, spec: KeyGenParameterSpec): Boolean {
        return try {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                algorithm,
                KEYSTORE_PROVIDER
            )
            keyPairGenerator.initialize(spec)
            keyPairGenerator.generateKeyPair()
            true
        } catch (e: ProviderException) {
            e.printStackTrace()
            false
        }
    }

    fun generateSymmetricKey(algorithm: String?, spec: KeyGenParameterSpec): Boolean {
        return try {
            val keyGenerator = KeyGenerator.getInstance(
                algorithm,
                KEYSTORE_PROVIDER
            )
            keyGenerator.init(spec)
            keyGenerator.generateKey()
            true
        } catch (e: ProviderException) {
            e.printStackTrace()
            false
        }
    }

    /**
     * Generate RSA key.
     *
     * @param alias alias
     * @return true:success; false:fail.
     */
    private fun generateRSA(alias: String): Boolean {
        return if (TextUtils.isEmpty(alias)) {
            false
        } else try {
            val builder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB, KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .setRandomizedEncryptionRequired(false)
                .setUserAuthenticationRequired(false)
                .setKeySize(RSA_SIZE)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                builder.setAttestationChallenge(challenge)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                if (isStrongBox) {
                    builder.setIsStrongBoxBacked(true)
                }
            }
            val keyGenParameterSpec = builder.build()
            generateKeyPair(KeyProperties.KEY_ALGORITHM_RSA, keyGenParameterSpec)
            true
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
            false
        } catch (e: NoSuchProviderException) {
            e.printStackTrace()
            false
        } catch (e: InvalidAlgorithmParameterException) {
            e.printStackTrace()
            false
        }
    }

    /**
     * Generate EC key.
     *
     * @param alias alias
     * @return true:success; false:fail.
     */
    private fun generateEC(alias: String): Boolean {
        return if (TextUtils.isEmpty(alias)) {
            false
        } else try {
            val builder = KeyGenParameterSpec.Builder(
                alias, KeyProperties.PURPOSE_VERIFY or KeyProperties.PURPOSE_SIGN
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
                .setRandomizedEncryptionRequired(false)
                .setUserAuthenticationRequired(false)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                builder.setAttestationChallenge(challenge)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                if (isStrongBox) {
                    builder.setIsStrongBoxBacked(true)
                }
            }
            val keyGenParameterSpec = builder.build()
            generateKeyPair(KeyProperties.KEY_ALGORITHM_EC, keyGenParameterSpec)
            true
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
            false
        } catch (e: NoSuchProviderException) {
            e.printStackTrace()
            false
        } catch (e: InvalidAlgorithmParameterException) {
            e.printStackTrace()
            false
        }
    }

    /**
     * Encrypted with RSA public key.
     *
     * @param alias alias
     * @param data  data
     * @return result.
     */
    fun encryptRSA(alias: String?, data: ByteArray?): ByteArray {
        return cryptPublic(alias, Cipher.ENCRYPT_MODE, data)
    }

    /**
     * Decrypted with RSA private key.
     *
     * @param alias alias
     * @param data  data
     * @return result
     */
    fun decryptRSA(alias: String?, data: ByteArray?): ByteArray {
        return cryptPrivate(alias, Cipher.DECRYPT_MODE, data)
    }

    /**
     * Encrypted or Decrypted with RSA public key.
     *
     * @param alias  alias
     * @param opmode Encrypted or Decrypted mode
     * @param data   data
     * @return result
     */
    fun cryptPublic(alias: String?, opmode: Int, data: ByteArray?): ByteArray {
        return cryptAsymmetric(
            alias, RSA_PUBLIC, opmode,
            KeyProperties.BLOCK_MODE_ECB, KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1, data
        )
    }

    /**
     * Encrypted or Decrypted with RSA private key.
     *
     * @param alias  alias
     * @param opmode Encrypted or Decrypted mode
     * @param data   data
     * @return result
     */
    fun cryptPrivate(alias: String?, opmode: Int, data: ByteArray?): ByteArray {
        return cryptAsymmetric(
            alias, RSA_PRIVATE, opmode,
            KeyProperties.BLOCK_MODE_ECB, KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1, data
        )
    }

    /**
     * Encrypted or Decrypted with RSA private key.
     *
     * @param alias     alias
     * @param option    [.RSA_PUBLIC] [.RSA_PRIVATE]
     * @param opmode    Encrypted or Decrypted mode
     * @param blockMode blockMode
     * @param padding   padding
     * @param data      data
     * @return result
     */
    fun cryptAsymmetric(
        alias: String?, option: Int, opmode: Int, blockMode: String,
        padding: String, data: ByteArray?
    ): ByteArray {
        val result = ByteArray(0)
        if (isNotKeyStoreBacked(alias)) {
            return result
        }
        if (TextUtils.isEmpty(blockMode) || TextUtils.isEmpty(padding)) {
            return result
        }
        return if (data == null || data.isEmpty()) {
            result
        } else try {
            val key = mKeyStore.getKey(alias, null) ?: return result
            val privateKey = key as PrivateKey
            if (checkNotSafe(privateKey)) {
                return result
            }
            if (option == RSA_PUBLIC) {
                val certificate = mKeyStore.getCertificate(alias) ?: return result
                val publicKey = certificate.publicKey ?: return result
                val cipher = Cipher.getInstance(
                    publicKey.algorithm + TRANSFORMATION_SEPARATOR + blockMode + TRANSFORMATION_SEPARATOR + padding
                )
                cipher.init(opmode, certificate)
                cipher.doFinal(data)
            } else if (option == RSA_PRIVATE) {
                val cipher = Cipher.getInstance(
                    privateKey.algorithm + TRANSFORMATION_SEPARATOR + blockMode + TRANSFORMATION_SEPARATOR + padding
                )
                cipher.init(opmode, privateKey)
                cipher.doFinal(data)
            } else {
                result
            }
        } catch (exception: KeyStoreException) {
            exception.printStackTrace()
            result
        } catch (exception: NoSuchAlgorithmException) {
            exception.printStackTrace()
            result
        } catch (exception: UnrecoverableEntryException) {
            exception.printStackTrace()
            result
        } catch (exception: NoSuchPaddingException) {
            exception.printStackTrace()
            result
        } catch (exception: InvalidKeyException) {
            exception.printStackTrace()
            result
        } catch (exception: BadPaddingException) {
            exception.printStackTrace()
            result
        } catch (exception: IllegalBlockSizeException) {
            exception.printStackTrace()
            result
        }
    }

    /**
     * Generate AES key.
     *
     * @param alias alias
     * @return true:success; false:fail.
     */
    private fun generateAES(alias: String): Boolean {
        return if (TextUtils.isEmpty(alias)) {
            false
        } else try {
            val builder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(
                    KeyProperties.ENCRYPTION_PADDING_NONE,
                    KeyProperties.ENCRYPTION_PADDING_PKCS7
                )
                .setUserAuthenticationRequired(false)
                .setRandomizedEncryptionRequired(false)
                .setKeySize(AES_LENGTH)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                if (isStrongBox) {
                    builder.setIsStrongBoxBacked(true)
                }
            }
            val keyGenParameterSpec = builder.build()
            generateSymmetricKey(KeyProperties.KEY_ALGORITHM_AES, keyGenParameterSpec)
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
            false
        } catch (e: NoSuchProviderException) {
            e.printStackTrace()
            false
        } catch (e: InvalidAlgorithmParameterException) {
            e.printStackTrace()
            false
        }
    }

    /**
     * Encrypted or Decrypted with AES key.
     *
     * @param alias     alias
     * @param opmode    [Cipher.ENCRYPT_MODE] or [Cipher.DECRYPT_MODE]
     * @param blockMode 1:ECB; 2:CBC
     * @param data      data
     * @return result
     */
    fun cryptSymmetric(alias: String?, opmode: Int, blockMode: Int, data: ByteArray?): ByteArray {
        return if (blockMode == 1) {
            cryptECB(alias, opmode, data)
        } else if (blockMode == 2) {
            cryptCBC(alias, opmode, data)
        } else {
            ByteArray(0)
        }
    }

    /**
     * Use the AES key to use the CBC block mode for encryption and decryption.
     *
     * @param alias  alias
     * @param opmode [Cipher.ENCRYPT_MODE] or [Cipher.DECRYPT_MODE]
     * @param data   data
     * @return result
     */
    fun cryptCBC(alias: String?, opmode: Int, data: ByteArray?): ByteArray {
        return cryptAES(
            alias, KeyProperties.BLOCK_MODE_CBC,
            KeyProperties.ENCRYPTION_PADDING_PKCS7, opmode, CBC_IV, data
        )
    }

    /**
     * Use the AES key to use the CBC block mode for encryption and decryption.
     *
     * @param alias  alias
     * @param opmode [Cipher.ENCRYPT_MODE] or [Cipher.DECRYPT_MODE]
     * @param data   data
     * @return result
     */
    fun cryptECB(alias: String?, opmode: Int, data: ByteArray?): ByteArray {
        return cryptAES(
            alias, KeyProperties.BLOCK_MODE_ECB,
            KeyProperties.ENCRYPTION_PADDING_PKCS7, opmode, null, data
        )
    }

    /**
     * Encrypted or Decrypted with AES key.
     *
     * @param alias     alias
     * @param blockMode blockMode
     * @param padding   padding
     * @param opmode    [Cipher.ENCRYPT_MODE] or [Cipher.DECRYPT_MODE]
     * @param iv        The initial vector, may be null.
     * @param data      data
     * @return result
     */
    fun cryptAES(
        alias: String?, blockMode: String, padding: String, opmode: Int, iv: ByteArray?,
        data: ByteArray?
    ): ByteArray {
        return cryptSymmetric(
            alias, KeyProperties.KEY_ALGORITHM_AES, blockMode,
            padding, opmode, iv, data
        )
    }

    /**
     * Encrypted or Decrypted with key.
     *
     * @param alias     alias
     * @param algorithm algorithm
     * @param blockMode blockMode
     * @param padding   padding
     * @param opmode    [Cipher.ENCRYPT_MODE] or [Cipher.DECRYPT_MODE]
     * @param iv        The initial vector, may be null.
     * @param data      data
     * @return result
     */
    fun cryptSymmetric(
        alias: String?, algorithm: String, blockMode: String, padding: String,
        opmode: Int, iv: ByteArray?, data: ByteArray?
    ): ByteArray {
        return cryptSymmetric(alias, algorithm, blockMode, padding, opmode, iv, data, false)
    }

    /**
     * Encrypted or Decrypted with key.
     *
     * @param alias     alias
     * @param algorithm algorithm
     * @param blockMode blockMode
     * @param padding   padding
     * @param opmode    [Cipher.ENCRYPT_MODE] or [Cipher.DECRYPT_MODE]
     * @param iv        The initial vector, may be null.
     * @param data      data
     * @param authRequired
     * @return result
     */
    fun cryptSymmetric(
        alias: String?, algorithm: String, blockMode: String, padding: String,
        opmode: Int, iv: ByteArray?, data: ByteArray?, authRequired: Boolean
    ): ByteArray {
        var nowIv = iv
        val result = ByteArray(0)
        if (isNotKeyStoreBacked(alias)) {
            return result
        }
        if (TextUtils.isEmpty(algorithm) || TextUtils.isEmpty(blockMode) || TextUtils.isEmpty(
                padding
            )
        ) {
            return result
        }
        return if (notFormatInputData(data)) {
            result
        } else try {
            val key = mKeyStore.getKey(alias, null)
            if (checkNotSafe(key)) {
                return result
            }
            val cipher = Cipher.getInstance(
                algorithm + TRANSFORMATION_SEPARATOR + blockMode + TRANSFORMATION_SEPARATOR + padding
            )
            if (KeyProperties.BLOCK_MODE_CBC == blockMode) {
                if (nowIv == null) {
                    nowIv = CBC_IV
                }
                cipher.init(opmode, key, IvParameterSpec(nowIv))
            } else {
                cipher.init(opmode, key)
            }
            if (authRequired) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    biometricPrompt = BiometricPrompt.Builder(this.mContextWeakReference?.get())
                        .setTitle("Biometric decrypt for my app")
                        .setSubtitle("Decrypt in using your biometric credential")
                        .setNegativeButton(
                            "Use account password",
                            executor,
                            { _, _ -> ByteArray(0) })
                        .build()
                    biometricPrompt.authenticate(
                        BiometricPrompt.CryptoObject(cipher),
                        CancellationSignal(),
                        executor,
                        object : BiometricPrompt.AuthenticationCallback() {
                            override fun onAuthenticationError(
                                errorCode: Int,
                                errString: CharSequence?
                            ) {
                                super.onAuthenticationError(errorCode, errString)
                                ByteArray(0)
                            }

                            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                super.onAuthenticationSucceeded(result)
                                result.cryptoObject.cipher?.doFinal(data)
                            }

                            override fun onAuthenticationFailed() {
                                super.onAuthenticationFailed()
                                ByteArray(0)
                            }
                        }
                    )
                } else {
                    cipher.doFinal(data)
                }
            } else {
                cipher.doFinal(data)
            }
            result
        } catch (e: KeyStoreException) {
            e.printStackTrace()
            result
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
            result
        } catch (e: UnrecoverableKeyException) {
            e.printStackTrace()
            result
        } catch (e: NoSuchPaddingException) {
            e.printStackTrace()
            result
        } catch (e: InvalidAlgorithmParameterException) {
            e.printStackTrace()
            result
        } catch (e: InvalidKeyException) {
            e.printStackTrace()
            result
        } catch (e: BadPaddingException) {
            e.printStackTrace()
            result
        } catch (e: IllegalBlockSizeException) {
            e.printStackTrace()
            result
        }
    }

    private fun notFormatInputData(data: ByteArray?): Boolean {
        return data == null || data.isEmpty()
    }

    /**
     * Check whether the key is stored in hardware.
     *
     * @param key key
     * @return true:Not safe; false: safe.
     */
    private fun checkNotSafe(key: Key): Boolean {
        return !isInsideSecureHardware(key)
    }

    /**
     * Initialize the KeyStore.
     */
    private fun initKeyStore() {
        try {
            mKeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
            mKeyStore.load(null)
        } catch (e: KeyStoreException) {
            e.printStackTrace()
        } catch (e: CertificateException) {
            e.printStackTrace()
        } catch (e: IOException) {
            e.printStackTrace()
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
        }
    }

    /**
     * Check whether the key exists in the KeyStore.
     *
     * @param alias alias
     * @return true: not exist; false: exist.
     */
    private fun isNotKeyStoreBacked(alias: String?): Boolean {
        return !isKeyStoreBacked(alias)
    }

    public fun isKeyStoreBacked(alias: String?): Boolean {
        return if (TextUtils.isEmpty(alias)) {
            false
        } else try {
            mKeyStore.containsAlias(alias)
        } catch (e: KeyStoreException) {
            e.printStackTrace()
            false
        }
    }

    /**
     * Check whether the key is stored in hardware.
     *
     * @param key key
     * @return true: key resides inside secure hardware; false: key resides not inside secure hardware.
     */
    private fun isInsideSecureHardware(key: Key?): Boolean {
        return if (key == null) {
            false
        } else try {
            var keyInfo: KeyInfo? = null
            if (key is PrivateKey) {
                val keyFactory = KeyFactory.getInstance(
                    key.getAlgorithm(),
                    KEYSTORE_PROVIDER
                )
                keyInfo = keyFactory.getKeySpec(key, KeyInfo::class.java)
            } else if (key is SecretKey) {
                val secretKeyFactory = SecretKeyFactory.getInstance(
                    key.getAlgorithm(),
                    KEYSTORE_PROVIDER
                )
                keyInfo =
                    secretKeyFactory.getKeySpec(key as SecretKey?, KeyInfo::class.java) as KeyInfo
            }
            keyInfo?.isInsideSecureHardware ?: false
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
            false
        } catch (e: InvalidKeySpecException) {
            e.printStackTrace()
            false
        } catch (e: NoSuchProviderException) {
            e.printStackTrace()
            false
        }
    }

    /**
     * Check whether the key is stored in hardware.
     *
     * @param alias alias
     * @return true: key resides inside secure hardware; false: key resides not inside secure hardware.
     */
    fun isInsideSecureHardware(alias: String?): Boolean {
        if (TextUtils.isEmpty(alias)) {
            return false
        }
        return if (isNotKeyStoreBacked(alias)) {
            false
        } else try {
            val key = mKeyStore.getKey(alias, null) ?: return false
            isInsideSecureHardware(key)
        } catch (exception: KeyStoreException) {
            exception.printStackTrace()
            false
        } catch (exception: NoSuchAlgorithmException) {
            exception.printStackTrace()
            false
        } catch (exception: UnrecoverableKeyException) {
            exception.printStackTrace()
            false
        }
    }

    @get:RequiresApi(api = Build.VERSION_CODES.P)
    val isStrongBox: Boolean
        get() {
            val context = mContextWeakReference!!.get() ?: return false
            val packageManager = context.packageManager ?: return false
            return packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        }

    fun getCertificate(alias: String?): Certificate? {
        if (TextUtils.isEmpty(alias)) {
            return null
        }
        if (isNotKeyStoreBacked(alias)) {
            return null
        }
        return mKeyStore.getCertificate(alias)
    }

    fun getCertificateChain(alias: String?): Array<Certificate> {
        try {
            if (TextUtils.isEmpty(alias)) {
                return emptyArray()
            }
            if (isNotKeyStoreBacked(alias)) {
                return emptyArray()
            }
            return mKeyStore.getCertificateChain(alias)
        } catch (exception: KeyStoreException) {
            exception.printStackTrace()
            return emptyArray()
        }
    }

    fun sign(alias: String?, data: ByteArray): ByteArray? {
        return when {
            TextUtils.isEmpty(alias) -> {
                null
            }
            isNotKeyStoreBacked(alias) -> {
                null
            }
            else -> {
                val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
                signature.initSign(mKeyStore.getKey(alias, null) as PrivateKey?)
                signature.update(data)
                signature.sign()
            }
        }
    }

    fun verify(alias: String?, data: ByteArray, sign: ByteArray): Boolean {
        return when {
            TextUtils.isEmpty(alias) -> {
                false
            }
            isNotKeyStoreBacked(alias) -> {
                false
            }
            else -> {
                val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
                signature.initVerify(mKeyStore.getCertificate(alias))
                signature.update(data)
                signature.verify(sign)
            }
        }
    }

    companion object {
        @Volatile
        private var instance: KeyStoreHelper? = null
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val TRANSFORMATION_SEPARATOR = "/"
        private const val AES_LENGTH = 256
        private const val RSA_PUBLIC = 1
        private const val RSA_PRIVATE = 2
        private const val RSA_SIZE = 2048
        private val CBC_IV = ByteArray(16)
        private const val EC_CURVE = "secp256r1"
        private const val SIGNATURE_ALGORITHM = "SHA256WithECDSA"

        fun getInstance(context: Context) = instance ?: synchronized(this) {
            instance ?: KeyStoreHelper(context).also { instance = it }
        }

        private val challenge: ByteArray
            get() {
                val random = SecureRandom()
                val challenge = ByteArray(32)
                random.nextBytes(challenge)
                return challenge
            }
    }

    init {
        if (mContextWeakReference == null) {
            mContextWeakReference = WeakReference(context)
        }
        executor = ContextCompat.getMainExecutor(this.mContextWeakReference?.get())
        initKeyStore()
    }
}