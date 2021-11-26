package com.pax.jc.androidkeystore

import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.annotation.RequiresApi

class MainActivity : AppCompatActivity() {
    private val keyStoreProxy = KeyStoreProxy()
    private lateinit var result: TextView
    @RequiresApi(Build.VERSION_CODES.P)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        keyStoreProxy.init(this@MainActivity)
        result = findViewById(R.id.result_tv)
        findViewById<Button>(R.id.generate_key_btn).setOnClickListener {
            val b = keyStoreProxy.generateRSAKey()
            showResult("GenerateKey:$b")
        }
        findViewById<Button>(R.id.key_test_btn).setOnClickListener {
            val b = keyStoreProxy.encryptAndDecryptData()
            showResult("EncryptAndDecryptData:$b")
        }
        findViewById<Button>(R.id.delete_key_btn).setOnClickListener {
            val b = keyStoreProxy.deleteKey()
            showResult("DeleteKey:$b")
        }

    }

    private fun showResult(msg: String) {
        result.append(msg + '\n')
    }
}