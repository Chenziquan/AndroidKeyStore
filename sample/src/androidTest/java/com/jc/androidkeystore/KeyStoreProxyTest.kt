package com.jc.androidkeystore

import androidx.test.platform.app.InstrumentationRegistry
import junit.framework.TestCase

/**
 * @author JQChen.
 * @date on 11/24/2021.
 */
class KeyStoreProxyTest : TestCase() {
    private val keyStoreProxy:KeyStoreProxy = KeyStoreProxy()

    public override fun setUp() {
        super.setUp()
        keyStoreProxy.init(InstrumentationRegistry.getInstrumentation().targetContext)
    }

    public override fun tearDown() {}

    fun testGenerateRSAKey() {
        assertTrue(keyStoreProxy.generateRSAKey())
    }

    fun testEncryptData() {
        assertTrue(keyStoreProxy.encryptAndDecryptData())
    }

    fun testDeleteKey() {
        assertTrue(keyStoreProxy.deleteKey())
    }
}
