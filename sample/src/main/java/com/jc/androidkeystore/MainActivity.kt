package com.jc.androidkeystore

import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.security.keystore.KeyProperties
import android.view.View
import android.widget.AdapterView
import android.widget.RadioGroup
import androidx.appcompat.widget.*
import androidx.lifecycle.Observer
import androidx.lifecycle.ViewModelProvider

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        KeyStoreProxy.instance.init(this@MainActivity)

        val viewModel =
            ViewModelProvider(this@MainActivity, ViewModelFactory()).get(MainViewModel::class.java)
        val algorithmRG = findViewById<RadioGroup>(R.id.alg_rg)
        val blockModeRG = findViewById<RadioGroup>(R.id.block_mode_rg)
        val paddingRG = findViewById<RadioGroup>(R.id.padding_rg)
        val actionRG = findViewById<RadioGroup>(R.id.action_rg)
        val authSW = findViewById<SwitchCompat>(R.id.auth_sw)
        val keyLengthSp = findViewById<AppCompatSpinner>(R.id.key_length_sp)
        val inputET = findViewById<AppCompatEditText>(R.id.input_et)
        val confirmBtn = findViewById<AppCompatButton>(R.id.confirm_button)
        val resultTV = findViewById<AppCompatTextView>(R.id.result_tv)

        algorithmRG.setOnCheckedChangeListener { _, checkedId ->
            when (checkedId) {
                R.id.alg_aes -> viewModel.algorithm(KeyProperties.KEY_ALGORITHM_AES)
                R.id.alg_rsa -> viewModel.algorithm(KeyProperties.KEY_ALGORITHM_RSA)
                R.id.alg_ec -> viewModel.algorithm(KeyProperties.KEY_ALGORITHM_EC)
            }
        }

        blockModeRG.setOnCheckedChangeListener { _, checkedId ->
            when (checkedId) {
                R.id.block_mode_ecb -> viewModel.blockMode(KeyProperties.BLOCK_MODE_ECB)
                R.id.block_mode_cbc -> viewModel.blockMode(KeyProperties.BLOCK_MODE_CBC)
                R.id.block_mode_ctr -> viewModel.blockMode(KeyProperties.BLOCK_MODE_CTR)
                R.id.block_mode_gcm -> viewModel.blockMode(KeyProperties.BLOCK_MODE_GCM)
            }
        }

        paddingRG.setOnCheckedChangeListener { _, checkedId ->
            when (checkedId) {
                R.id.padding_no -> viewModel.padding(KeyProperties.ENCRYPTION_PADDING_NONE)
                R.id.padding_pkcs7 -> viewModel.padding(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                R.id.padding_pkcs1 -> viewModel.padding(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                R.id.padding_oaep -> viewModel.padding(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            }
        }

        authSW.setOnCheckedChangeListener { _, isChecked -> viewModel._authRequired(isChecked) }

        keyLengthSp.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: AdapterView<*>?,
                view: View?,
                position: Int,
                id: Long
            ) {
                viewModel.keyLength(
                    resources.getStringArray(
                        R.array.key_length
                    )[position].toInt()
                )
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {
            }
        }

        actionRG.setOnCheckedChangeListener { _, checkedId ->
            viewModel.actionID(checkedId)
        }

        confirmBtn.setOnClickListener {
            /*when (viewModel.actionID.value) {
                R.id.action_generate -> viewModel.generateKey()
                R.id.action_delete -> viewModel.deleteKey()
                R.id.action_encrypt -> viewModel.encrypt(inputET.text?.trim().toString())
                R.id.action_decrypt -> viewModel.decrypt()
                else -> resultTV.text = "Do nothing!"
            }*/
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                KeyStoreProxy.instance.encryptAndDecryptData()
            }
        }

        viewModel.actionResult.observe(this, Observer {
            val result = it ?: return@Observer
            resultTV.text = result
        })


    }
}