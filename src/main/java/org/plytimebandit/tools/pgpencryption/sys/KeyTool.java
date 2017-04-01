package org.plytimebandit.tools.pgpencryption.sys;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.inject.Inject;

import org.apache.commons.codec.binary.Base64;

import com.google.inject.name.Named;

public class KeyTool {

    private int keySize;
    private String algorithm;

    public KeyPair createKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
        generator.initialize(keySize, secureRandom);
        return generator.generateKeyPair();
    }

    public String getPublicKey(KeyPair keyPair) {
        return getPublicKey(keyPair.getPublic());
    }

    public String getPrivateKey(KeyPair keyPair) {
        return getPrivateKey(keyPair.getPrivate());
    }

    String getPrivateKey(PrivateKey privateKey) {
        return Base64.encodeBase64String(privateKey.getEncoded());
    }

    String getPublicKey(PublicKey publicKey) {
        return Base64.encodeBase64String(publicKey.getEncoded());
    }

    @Inject
    void setKeySize(@Named("keySize") int keySize) {
        this.keySize = keySize;
    }

    @Inject
    void setAlgorithm(@Named("algorithm") String algorithm) {
        this.algorithm = algorithm;
    }
}
