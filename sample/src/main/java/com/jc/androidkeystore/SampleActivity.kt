package com.jc.androidkeystore

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button

class SampleActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_sample)
        val keyStoreHelper2 = KeyStoreHelper2()

        findViewById<Button>(R.id.main_keychain_btn)
            .setOnClickListener { keyStoreHelper2.keyChainTest(this) }
    }
}