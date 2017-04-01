package org.plytimebandit.tools.pgpencryption.sys;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.inject.Inject;

import org.apache.commons.codec.binary.Base64;

import com.google.inject.name.Named;

public class KeyTool {

    @Inject @Named("keySize")
    private int keySize;

    @Inject @Named("algorithm")
    private String algorithm;

    @Inject
    public KeyPair createKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(keySize);
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
}
