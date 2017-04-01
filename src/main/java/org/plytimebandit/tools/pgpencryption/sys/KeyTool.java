package org.plytimebandit.tools.pgpencryption.sys;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.inject.Inject;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.crypto.CipherParameters;
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

    public String convertPublicKeyToString(KeyPair keyPair) {
        return convertToString(keyPair.getPublic());
    }

    public String convertPrivateKeyToString(KeyPair keyPair) {
        return convertToString(keyPair.getPrivate());
    }

    String convertToString(Key key) {
        return Base64.encodeBase64String(key.getEncoded());
    }

    public CipherParameters convertToPublicKey(File publicKeyFile) throws IOException {
        String publicKeyAsString = FileUtils.readFileToString(publicKeyFile, StandardCharsets.UTF_8);
        return PublicKeyFactory.createKey(Base64.decodeBase64(publicKeyAsString));
    }

    public CipherParameters convertToPublicKey(Key publicKey) throws IOException {
        return PublicKeyFactory.createKey(publicKey.getEncoded());
    }

    public AsymmetricKeyParameter convertToPrivateKey(File privateKeyFile) throws IOException {
        String privateKeyAsString = FileUtils.readFileToString(privateKeyFile, StandardCharsets.UTF_8);
        return PrivateKeyFactory.createKey(Base64.decodeBase64(privateKeyAsString));
    }

    public AsymmetricKeyParameter convertToPrivateKey(Key privateKey) throws IOException {
        return PrivateKeyFactory.createKey(privateKey.getEncoded());
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
