package com.jc.androidkeystore

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import javax.crypto.Cipher

/**
 * @author JQChen.
 * @date on 1/18/2022.
 */
class MainViewModel(private val mainRepository: MainRepository) : ViewModel() {

    private val _algorithm = MutableLiveData<String>()
    private val _blockMode = MutableLiveData<String>()
    private val _padding = MutableLiveData<String>()
    private val _keyLength = MutableLiveData<Int>()
    private val _authRequired = MutableLiveData<Boolean>()
    private val _ciphertext = MutableLiveData<ByteArray>()

    private val _actionID = MutableLiveData<Int>()
    val actionID: LiveData<Int> = _actionID

    private val _actionResult = MutableLiveData<String>()
    val actionResult: LiveData<String> = _actionResult

    fun algorithm(string: String) {
        _algorithm.value = string
    }

    fun blockMode(string: String) {
        _blockMode.value = string
    }

    fun padding(string: String) {
        _padding.value = string
    }

    fun keyLength(length: Int) {
        _keyLength.value = length
    }

    fun _authRequired(boolean: Boolean) {
        _authRequired.value = boolean
    }

    fun actionID(int: Int) {
        _actionID.value = int
    }

    fun generateKey() {
        val generateKey =
            mainRepository.generateKey(
                _algorithm.value ?: "",
                _blockMode.value ?: "",
                _padding.value ?: "",
                _keyLength.value ?: 128,
                _authRequired.value ?: false
            )
        if (generateKey is Result.Success) {
            if (generateKey.data) {
                _actionResult.value = "Generate key success!"
            } else {
                _actionResult.value = "Key exist!"
            }
        } else if (generateKey is Result.Error) {
            _actionResult.value = generateKey.data
        }
    }

    fun deleteKey(
    ) {
        val deleteKey = mainRepository.deleteKey(
            _algorithm.value ?: "",
            _blockMode.value ?: "",
            _padding.value ?: "",
            _keyLength.value ?: 128
        )
        if (deleteKey is Result.Success) {
            if (deleteKey.data) {
                _actionResult.value = "Delete key success!"
            } else {
                _actionResult.value = "Delete key fail!"
            }
        } else if (deleteKey is Result.Error) {
            _actionResult.value = deleteKey.data
        }
    }

    fun encrypt(data: String) {
        viewModelScope.launch {
            val encrypt = mainRepository.encryptOrDecrypt(
                _algorithm.value ?: "",
                _blockMode.value ?: "",
                _padding.value ?: "",
                _keyLength.value ?: 128,
                Cipher.ENCRYPT_MODE,
                data.toByteArray(Charsets.UTF_8),
                _authRequired.value ?: false
            )
            if (encrypt is Result.Success) {
                _ciphertext.value = encrypt.data
                _actionResult.postValue("Ciphertext:${Tools.parseByte2HexStr(encrypt.data)}")
            } else if (encrypt is Result.Error) {
                _actionResult.postValue(encrypt.data)
            }
        }
    }

    fun decrypt() {
        viewModelScope.launch {
            if (_ciphertext.value == null) {
                _actionResult.postValue("Cipher text is null")
            }
            val encrypt = mainRepository.encryptOrDecrypt(
                _algorithm.value ?: "",
                _blockMode.value ?: "",
                _padding.value ?: "",
                _keyLength.value ?: 128,
                Cipher.DECRYPT_MODE,
                _ciphertext.value ?: ByteArray(0),
                _authRequired.value ?: false
            )
            if (encrypt is Result.Success) {
                _actionResult.postValue("Plaintext:${String(encrypt.data, Charsets.UTF_8)}")
            } else if (encrypt is Result.Error) {
                _actionResult.postValue(encrypt.data)
            }
        }

    }


}