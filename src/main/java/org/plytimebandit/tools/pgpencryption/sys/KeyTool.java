package org.plytimebandit.tools.pgpencryption.sys;

import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.inject.Inject;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

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

    public String encodePublicKeyBase64(KeyPair keyPair) {
        return encodeKeyBase64(keyPair.getPublic());
    }

    public String encodePrivateKeyBase64(KeyPair keyPair) {
        return encodeKeyBase64(keyPair.getPrivate());
    }

    String encodeKeyBase64(Key key) {
        return Base64.encodeBase64String(key.getEncoded());
    }

    public AsymmetricKeyParameter decodePublicKeyBase64(String publicKey) throws IOException {
        return PublicKeyFactory.createKey(Base64.decodeBase64(publicKey));
    }

    public AsymmetricKeyParameter decodePrivateKeyBase64(String privateKey) throws IOException {
        return PrivateKeyFactory.createKey(Base64.decodeBase64(privateKey));
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
