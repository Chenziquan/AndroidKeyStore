package com.jc.androidkeystore

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider

/**
 * ViewModel provider factory to instantiate LoginViewModel.
 * Required given LoginViewModel has a non-empty constructor
 */
class ViewModelFactory : ViewModelProvider.Factory {

    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        when {
            modelClass.isAssignableFrom(MainViewModel::class.java) -> {
                return MainViewModel(
                    mainRepository = MainRepository(
                        dataSource = MainDataSource()
                    )
                ) as T
            }

            else -> throw IllegalArgumentException("Unknown ViewModel class")
        }
    }
}