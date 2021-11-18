package com.pax.jc.androidkeystore

import android.app.Instrumentation
import android.security.keystore.KeyProperties
import androidx.test.platform.app.InstrumentationRegistry
import junit.framework.TestCase
import javax.crypto.Cipher
import kotlin.random.Random

/**
 * @author JQChen.
 * @date on 11/9/2021.
 */
class KeyStoreHelperTest : TestCase() {

    var keyStoreHelper: KeyStoreHelper? = null
    override fun setUp() {
        super.setUp()
        if (keyStoreHelper == null) {
            keyStoreHelper =
                KeyStoreHelper.getInstance(InstrumentationRegistry.getInstrumentation().targetContext)
        }
    }

    override fun tearDown() {
        super.tearDown()
    }

    fun testSaveAESKey() {
        val alias = "AES_KEY"
        val keyValue = ByteArray(32)
        Random.Default.nextBytes(keyValue)
        var b = keyStoreHelper?.saveAESKey(alias, keyValue)
        if (b != null) {
            assertTrue(b)
        } else {
            fail("save key")
        }
        b = keyStoreHelper?.isKeyStoreBacked(alias)
        if (b != null) {
            assertTrue(b)
        } else {
            fail("isKeyStoreBacked")
        }
        b = keyStoreHelper?.deleteKey(alias)
        if (b != null) {
            assertTrue(b)
        } else {
            fail("deleteKey")
        }
    }


    fun testGenerateAESKey() {
        val alias = "AES_KEY"
        val boolean = keyStoreHelper?.generateKey(KeyProperties.KEY_ALGORITHM_AES, alias)
        if (boolean != null) {
            assertTrue(boolean)
        } else {
            fail("generateKey")
        }
        val plainText = "This is test".toByteArray(charset = Charsets.UTF_8)
        val cipherText = keyStoreHelper?.cryptCBC(alias, Cipher.ENCRYPT_MODE, plainText)
        assertNotNull(cipherText)
        val plainText1 = keyStoreHelper?.cryptCBC(alias, Cipher.DECRYPT_MODE, cipherText)
        assertEquals(String(plainText), plainText1?.let { String(it) })
        val b = keyStoreHelper?.deleteKey(alias)
        if (b != null) {
            assertTrue(b)
        } else {
            fail("deleteKey")
        }
    }

    fun testGenerateRSAKey() {
        val alias = "RSA_KEY"
        val b = try {
            val boolean = keyStoreHelper?.generateKey(KeyProperties.KEY_ALGORITHM_RSA, alias)
            if (boolean != null) {
                assertTrue(boolean)
            } else {
                fail("generateKey")
            }
            val plainText = "This is test".toByteArray(charset = Charsets.UTF_8)
            val cipherText = keyStoreHelper?.encryptRSA(alias, plainText)
            assertNotNull(cipherText)
            val plainText1 = keyStoreHelper?.decryptRSA(alias, cipherText)
            assertEquals(String(plainText), plainText1?.let { String(it) })
        } finally {
            val b = keyStoreHelper?.deleteKey(alias)
            if (b != null) {
                assertTrue(b)
            } else {
                fail("deleteKey")
            }
        }

    }

    fun testGenerateECKey() {
        val alias = "EC_KEY"
        val b = try {
            val boolean = keyStoreHelper?.generateKey(KeyProperties.KEY_ALGORITHM_EC, alias)
            if (boolean != null) {
                assertTrue(boolean)
            } else {
                fail("generateKey")
            }
            val plainText = "This is test".toByteArray(charset = Charsets.UTF_8)
            val sign = keyStoreHelper?.sign(alias, plainText)
            assertNotNull(sign)
            val verify = sign?.let { keyStoreHelper?.verify(alias, plainText, it) }
            if (verify != null) {
                assertTrue(verify)
            } else {
                fail("verify")
            }
        } finally {
            val b = keyStoreHelper?.deleteKey(alias)
            if (b != null) {
                assertTrue(b)
            } else {
                fail("deleteKey")
            }
        }

    }
}