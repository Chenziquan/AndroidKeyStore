package com.jc.androidkeystore

import android.app.Activity
import android.content.Context
import android.security.KeyChain
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import javax.crypto.KeyGenerator

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
        val provider = "AndroidKeyStore"
        // init KeyGenParameterSpec.Builder
        val alias = "AES_KEY"
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).setKeySize(128)
            .build()
        // init keyGenerator
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, provider)
        keyGenerator.init(keyGenParameterSpec)
        // generate key
        val secureKey = keyGenerator.generateKey()
    }

    fun getKey(context: Context) {
        val provider = "AndroidKeyStore"
        // init android keystore
        val keyStore = KeyStore.getInstance(provider)
        keyStore.load(null)
        val alias = "AES_KEY"
        val key = keyStore.getKey(alias, null)
    }

    fun generateRSAKey(context: Context) {
        val provider = "AndroidKeyStore"
        // init android keystore
        val keyStore = KeyStore.getInstance(provider)
        keyStore.load(null)
        // init KeyGenParameterSpec.Builder
        val alias = "RSA_KEY"
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).setKeySize(512)
            .build()
        // init keyPairGenerator
        val keyPairGenerator =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, provider)
        keyPairGenerator.initialize(keyGenParameterSpec)
        // generate key
        val keyPair = keyPairGenerator.genKeyPair()
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

}