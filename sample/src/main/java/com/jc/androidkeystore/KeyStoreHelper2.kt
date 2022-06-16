package com.jc.androidkeystore

import android.app.Activity
import android.content.Context
import android.os.Build
import android.security.KeyChain
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.google.crypto.tink.aead.subtle.AesGcmSiv
import com.google.crypto.tink.subtle.Hkdf
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.*
import java.security.cert.Certificate
import java.security.spec.ECGenParameterSpec
import javax.crypto.*

/**
 * @author JQChen.
 * @date on 2/23/2022.
 */
class KeyStoreHelper2 {

    /**
     * 生成AES密钥保存在Android KeyStore中
     * @param context
     */
    fun generateAESKey(context: Context) {
        // init KeyGenParameterSpec.Builder
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            "AES",
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).setKeySize(128)
            .build()
        // init keyGenerator
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore"
        )
        keyGenerator.init(keyGenParameterSpec)
        // generate key
        val secureKey = keyGenerator.generateKey()
    }

    fun saveAESKey() {
        val key128Value = ByteArray(size = 128) { i -> i.toByte() }
        // init android keystore
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        // save AES Key
        keyStore.setKeyEntry("AES128", key128Value, null)

    }

    fun saveRSAKey() {
        // certificate
        val certificate: Certificate
        // privateKey
        val privateKey: PrivateKey
        // init android keystore
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        // save RSA Key
        // keyStore.setKeyEntry("RSA", privateKey.encoded, arrayOf(certificate))
    }

    fun getKey(context: Context) {
        val provider = "AndroidKeyStore"
        // init android keystore
        val keyStore = KeyStore.getInstance(provider)
        keyStore.load(null)
        val alias = "AES_KEY"
        val key = keyStore.getKey(alias, null)
    }

    fun getAESKey() {
        // init keystore
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        // get AES key
        val key: Key? = keyStore.getKey("AES", null)
        val secretKey: SecretKey = key as SecretKey
    }

    fun getRSAKey() {
        // init keystore
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        //get RSA Certificate
        val certificate = keyStore.getCertificate("RSA")

        // get RSA private key
        val privateKey: PrivateKey = keyStore.getKey("RSA", null)
                as PrivateKey
    }

    @RequiresApi(Build.VERSION_CODES.P)
    fun generateRSAKey(context: Context) {
        // init android keystore
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        // init KeyGenParameterSpec.Builder
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            "AES",
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).setKeySize(512)
            .setIsStrongBoxBacked(true)
            .build()
        // init keyPairGenerator
        val keyPairGenerator =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
        keyPairGenerator.initialize(keyGenParameterSpec)
        // generate key
        val keyPair = keyPairGenerator.genKeyPair()
    }

    fun generateECKey() {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
        )
        keyPairGenerator.initialize(
            KeyGenParameterSpec.Builder("EC", KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(
                    KeyProperties.DIGEST_SHA256,
                    KeyProperties.DIGEST_SHA384,
                    KeyProperties.DIGEST_SHA512
                ) // Only permit the private key to be used if the user authenticated
                // within the last five minutes.
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(5 * 60)
                .build()
        )
        val keyPair = keyPairGenerator.generateKeyPair()
    }

    fun insideSecureHardwareRSA() {
        // init android keystore
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        // get Key
        val key = keyStore.getKey("RSA", null)
        val keyFactory = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
        val keyInfo = keyFactory.getKeySpec(key, KeyInfo::class.java)
        val isInsideSecureHardware = keyInfo.isInsideSecureHardware
    }

    fun insideSecureHardwareAES() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        // get Key
        val key: SecretKey = keyStore.getKey("AES", null) as SecretKey
        val secretKeyFactory = SecretKeyFactory.getInstance(
            key.algorithm, "AndroidKeyStore"
        )
        val keyInfo = secretKeyFactory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
        val isInsideSecureHardware = keyInfo.isInsideSecureHardware
    }

    fun insideSecureHardware(key: Key): Boolean {
        val provider = "AndroidKeyStore"
        val keyFactory = KeyFactory.getInstance(key.algorithm, provider)
        val keyInfo = keyFactory.getKeySpec(key, KeyInfo::class.java)
        return keyInfo.isInsideSecureHardware
    }

    fun keyChainTest(activity: Activity) {
        KeyChain.choosePrivateKeyAlias(
            activity,
            { alias -> println(alias) },
            arrayOf(KeyProperties.KEY_ALGORITHM_AES, KeyProperties.KEY_ALGORITHM_RSA),
            null,
            null, null
        )
    }

    fun cryptAES() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        // get Key
        val key = keyStore.getKey("AES", null)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // encrypt
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val cleartext = "This is cleartext".toByteArray()
        val ciphertext = cipher.doFinal(cleartext)

        // decrypt
        cipher.init(Cipher.DECRYPT_MODE, key)
        val decryptText = cipher.doFinal(ciphertext)
    }

    fun cryptRSA() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        // encrypt
        val publicKey = keyStore.getCertificate("RSA").publicKey
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val cleartext = "This is cleartext".toByteArray()
        val ciphertext = cipher.doFinal(cleartext)

        // decrypt
        val privateKey: PrivateKey = keyStore.getKey("RSA", null) as PrivateKey
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        val decryptText = cipher.doFinal(ciphertext)
    }

    fun signRSA() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        val signature = Signature.getInstance("SHA256withRSA/PSS")

        // sign
        val privateKey: PrivateKey = keyStore.getKey("RSA", null) as PrivateKey
        signature.initSign(privateKey)
        val text = "This is sign text".toByteArray()
        signature.update(text)
        val sign = signature.sign()

        // verify
        val publicKey = keyStore.getCertificate("RSA").publicKey
        signature.initVerify(publicKey)
        val verify = signature.verify(sign)
    }

    fun hmacSHA256() {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore"
        )
        keyGenerator.init(
            KeyGenParameterSpec.Builder("HMAC", KeyProperties.PURPOSE_SIGN).build()
        )
        val key = keyGenerator.generateKey()

        val mac = Mac.getInstance("HmacSHA256")
        mac.init(key)
        val text = "This is hmac text".toByteArray()
        val macText = mac.doFinal(text)
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    private fun ECAgreement(): ByteArray? {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )
            keyPairGenerator.initialize(
                KeyGenParameterSpec.Builder(
                    "eckeypair",
                    KeyProperties.PURPOSE_AGREE_KEY
                )
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .build()
            )
            val myKeyPair = keyPairGenerator.generateKeyPair()

            // Exchange public keys with server. A new ephemeral key MUST be used for every message.
            val serverEphemeralPublicKey: PublicKey? = null // Ephemeral key received from server.

            // Create a shared secret based on our private key and the other party's public key.
            val keyAgreement = KeyAgreement.getInstance("ECDH", "AndroidKeyStore")
            keyAgreement.init(myKeyPair.private)
            keyAgreement.doPhase(serverEphemeralPublicKey, true)
            val sharedSecret = keyAgreement.generateSecret()

            // sharedSecret cannot safely be used as a key yet. We must run it through a key derivation
            // function with some other data: "salt" and "info". Salt is an optional random value,
            // omitted in this example. It's good practice to include both public keys and any other
            // key negotiation data in info. Here we use the public keys and a label that indicates
            // messages encrypted with this key are coming from the server.
            val salt = byteArrayOf()
            val info = ByteArrayOutputStream()
            info.write("ECDH secp256r1 AES-256-GCM-SIV\u0000".toByteArray(StandardCharsets.UTF_8))
            info.write(myKeyPair.public.encoded)
            info.write(serverEphemeralPublicKey!!.encoded)

            // This example uses the Tink library and the HKDF key derivation function.
            val key = AesGcmSiv(
                Hkdf.computeHkdf(
                    "HMACSHA256", sharedSecret, salt, info.toByteArray(), 32
                )
            )
            val associatedData = byteArrayOf()
            val ciphertext = byteArrayOf()
            return key.decrypt(ciphertext, associatedData)
        } catch (e: IOException) {
            e.printStackTrace()
        } catch (e: GeneralSecurityException) {
            e.printStackTrace()
        }
        return null
    }

}