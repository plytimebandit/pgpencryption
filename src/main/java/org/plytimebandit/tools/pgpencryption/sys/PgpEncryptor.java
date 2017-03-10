package org.plytimebandit.tools.pgpencryption.sys;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

import javax.inject.Inject;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;

public class PgpEncryptor {

    private final KeyTool keyTool;

    private String readableText;

    @Inject
    public PgpEncryptor(KeyTool keyTool) {
        this.keyTool = keyTool;
    }

    public PgpEncryptor encrypt(String readableText) {
        this.readableText = readableText;
        return this;
    }

    public PgpEncryptor encrypt(File readableText) throws IOException {
        this.readableText = FileUtils.readFileToString(readableText, StandardCharsets.UTF_8);
        return this;
    }

    public String withKey(String keyFile) throws IOException, InvalidCipherTextException {
        return withKey(new File(keyFile));
    }

    public String withKey(File keyFile) throws IOException, InvalidCipherTextException {
        String key = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
        return exec(key);
    }

    public String withKey(PublicKey publicKey) throws IOException, InvalidCipherTextException {
        return exec(keyTool.getPublicKey(publicKey));
    }

    private String exec(String publicKeyString) throws IOException, InvalidCipherTextException {
        AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(Base64.decodeBase64(publicKeyString));

        PKCS1Encoding encoding = new PKCS1Encoding(new RSAEngine());
        encoding.init(true, publicKey);

        byte[] hexEncodedCipher = encoding.processBlock(
                readableText.getBytes(StandardCharsets.UTF_8), 0, readableText.length());
        return Hex.encodeHexString(hexEncodedCipher);
    }

}
