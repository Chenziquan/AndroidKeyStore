package com.jc.androidkeystore

/**
 * A generic class that holds a value with its loading status.
 * @param <T>
 * @param <S>
 */
sealed class Result<out T : Any, out S : Any> {

    data class Success<out T : Any>(val data: T) : Result<T, Nothing>()
    data class Error<out S : Any>(val data: S) : Result<Nothing, S>()

    override fun toString(): String {
        return when (this) {
            is Success<*> -> "Success[data=$data]"
            is Error<*> -> "Error[data=$data]"
        }
    }
}