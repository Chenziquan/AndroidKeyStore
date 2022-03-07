package com.jc.androidkeystore

import java.lang.StringBuilder
import java.util.*
import kotlin.experimental.and

/**
 * @author JQChen.
 * @date on 1/19/2022.
 */
object Tools {

    fun bcd2Str(b: ByteArray?): String? {
        return if (b == null) {
            null
        } else bcd2Str(b, b.size)
    }

    private val HEX_DIGITS = charArrayOf(
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
        'E', 'F'
    )

    private fun bcd2Str(b: ByteArray?, length: Int): String? {
        if (b == null) {
            return null
        }
        val sb = StringBuilder(length * 2)
        for (i in 0 until length) {
            sb.append(HEX_DIGITS[(b[i] and 0xF0.toByte()).toInt().shr(4)])
            sb.append(HEX_DIGITS[(b[i] and 0xF).toInt()])
        }

        return sb.toString()
    }

    fun str2Bcd(asc: String): ByteArray {
        var str = asc
        if (str.length % 2 != 0) {
            str = "0$str"
        }
        var len = str.length
        if (len >= 2) {
            len /= 2
        }
        val bbt = ByteArray(len)
        val abt = str.toByteArray()
        for (p in 0 until str.length / 2) {
            bbt[p] =
                ((strByte2Int(abt[2 * p]) shl 4) + strByte2Int(abt[2 * p + 1])).toByte()
        }
        return bbt
    }

    private fun strByte2Int(b: Byte): Int {
        val j: Int
        j = if (b >= 'a'.toByte() && b <= 'z'.toByte()) {
            b - 'a'.toByte() + 0x0A
        } else {
            if (b >= 'A'.toByte() && b <= 'Z'.toByte()) {
                b - 'A'.toByte() + 0x0A
            } else {
                b - '0'.toByte()
            }
        }
        return j
    }

    fun parseByte2HexStr(buf: ByteArray?): String {
        val sb = StringBuilder()

        for (i in buf!!.indices) {

            var hex = Integer.toHexString((buf[i]).toInt() and 0xFF)

            if (hex.length == 1) {

                hex = "0$hex"

            }

            sb.append(hex.toUpperCase(Locale.getDefault()))

        }

        return sb.toString()

    }
}

