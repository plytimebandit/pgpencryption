package org.plytimebandit.tools.pgpencryption.sys;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;

import javax.inject.Inject;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class PgpEncryptor {

    private final KeyTool keyTool;

    private byte[] readableText;

    @Inject
    public PgpEncryptor(KeyTool keyTool) {
        this.keyTool = keyTool;
    }

    public PgpEncryptor encrypt(String readableText) {
        this.readableText = readableText.getBytes(StandardCharsets.UTF_8);
        return this;
    }

    public PgpEncryptor encrypt(File readableText) throws IOException {
        this.readableText = FileUtils.readFileToByteArray(readableText);
        return this;
    }

    public String withKey(File keyFile) throws IOException, InvalidCipherTextException {
        String key = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
        return exec(key);
    }

    public String withKey(Key publicKey) throws IOException, InvalidCipherTextException {
        return exec(keyTool.encodeKeyBase64(publicKey));
    }

    private String exec(String publicKeyString) throws IOException, InvalidCipherTextException {
        AsymmetricKeyParameter publicKey = keyTool.decodePublicKeyBase64(publicKeyString);

        PKCS1Encoding encoding = new PKCS1Encoding(new RSAEngine());
        encoding.init(true, publicKey);

        int bufferSize = encoding.getInputBlockSize();

        StringBuilder result = new StringBuilder();

        byte[][] chunks = Tools.chunkArray(readableText, bufferSize);
        for (byte[] oneChunk : chunks) {
            byte[] encryptedData = encoding.processBlock(oneChunk, 0, Math.min(bufferSize, oneChunk.length));
            result.append(Hex.encodeHexString(encryptedData));
        }

        return result.toString();
    }

}
