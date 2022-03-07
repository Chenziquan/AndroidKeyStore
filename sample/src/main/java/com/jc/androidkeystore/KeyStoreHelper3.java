package com.jc.androidkeystore;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.google.crypto.tink.aead.subtle.AesGcmSiv;
import com.google.crypto.tink.subtle.Hkdf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import androidx.annotation.RequiresApi;

/**
 * @author JQChen.
 * @date on 2/25/2022.
 */
class KeyStoreHelper3 {

    private void ECSign() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder("key1", KeyProperties.PURPOSE_SIGN)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                            .setDigests(KeyProperties.DIGEST_SHA256,
                                    KeyProperties.DIGEST_SHA384,
                                    KeyProperties.DIGEST_SHA512)
                            // Only permit the private key to be used if the user authenticated
                            // within the last five minutes.
                            .setUserAuthenticationRequired(true)
                            .setUserAuthenticationValidityDurationSeconds(5 * 60)
                            .build());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(keyPair.getPrivate());


            // The key pair can also be obtained from the Android Keystore any time as follows:
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey("key1", null);
            PublicKey publicKey = keyStore.getCertificate("key1").getPublicKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException
                | InvalidKeyException | KeyStoreException | CertificateException | IOException |
                UnrecoverableKeyException e) {
            e.printStackTrace();
        }
    }

    private void RSASign() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(
                            "key1",
                            KeyProperties.PURPOSE_SIGN)
                            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                            .build());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            Signature signature = Signature.getInstance("SHA256withRSA/PSS");
            signature.initSign(keyPair.getPrivate());

            // The key pair can also be obtained from the Android Keystore any time as follows:
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey("key1", null);
            PublicKey publicKey = keyStore.getCertificate("key1").getPublicKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException |
                InvalidKeyException | KeyStoreException | CertificateException | IOException |
                UnrecoverableKeyException e) {
            e.printStackTrace();
        }
    }

    private void RSACrypt() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(
                            "key1",
                            KeyProperties.PURPOSE_DECRYPT)
                            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                            .build());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

            // The key pair can also be obtained from the Android Keystore any time as follows:
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey("key1", null);
            PublicKey publicKey = keyStore.getCertificate("key1").getPublicKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException |
                NoSuchPaddingException | InvalidKeyException | KeyStoreException | CertificateException |
                IOException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
    }

    private void AESCrypt() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            keyGenerator.init(
                    new KeyGenParameterSpec.Builder("key2",
                            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .build());
            SecretKey key = keyGenerator.generateKey();

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            // ...

            // The key can also be obtained from the Android Keystore any time as follows:
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            key = (SecretKey) keyStore.getKey("key2", null);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException |
                NoSuchPaddingException | InvalidKeyException | KeyStoreException | CertificateException |
                IOException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
    }

    private void HMAC() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore");
            keyGenerator.init(
                    new KeyGenParameterSpec.Builder("key2", KeyProperties.PURPOSE_SIGN).build());
            SecretKey key = keyGenerator.generateKey();
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            // ...

            // The key can also be obtained from the Android Keystore any time as follows:
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            key = (SecretKey) keyStore.getKey("key2", null);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException |
                InvalidKeyException | KeyStoreException | CertificateException | IOException |
                UnrecoverableKeyException e) {
            e.printStackTrace();
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.S)
    private byte[] ECAgreement() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(
                            "eckeypair",
                            KeyProperties.PURPOSE_AGREE_KEY)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                            .build());
            KeyPair myKeyPair = keyPairGenerator.generateKeyPair();

            // Exchange public keys with server. A new ephemeral key MUST be used for every message.
            PublicKey serverEphemeralPublicKey = null; // Ephemeral key received from server.

            // Create a shared secret based on our private key and the other party's public key.
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "AndroidKeyStore");
            keyAgreement.init(myKeyPair.getPrivate());
            keyAgreement.doPhase(serverEphemeralPublicKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();

            // sharedSecret cannot safely be used as a key yet. We must run it through a key derivation
            // function with some other data: "salt" and "info". Salt is an optional random value,
            // omitted in this example. It's good practice to include both public keys and any other
            // key negotiation data in info. Here we use the public keys and a label that indicates
            // messages encrypted with this key are coming from the server.
            byte[] salt = {};
            ByteArrayOutputStream info = new ByteArrayOutputStream();
            info.write("ECDH secp256r1 AES-256-GCM-SIV\0".getBytes(StandardCharsets.UTF_8));
            info.write(myKeyPair.getPublic().getEncoded());
            info.write(serverEphemeralPublicKey.getEncoded());

            // This example uses the Tink library and the HKDF key derivation function.
            AesGcmSiv key = new AesGcmSiv(Hkdf.computeHkdf(
                    "HMACSHA256", sharedSecret, salt, info.toByteArray(), 32));
            byte[] associatedData = {};
            byte[] ciphertext = {};
            return key.decrypt(ciphertext, associatedData);
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
        return null;
    }
}
