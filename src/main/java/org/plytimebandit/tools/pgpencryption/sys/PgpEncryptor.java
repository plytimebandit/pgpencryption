package org.plytimebandit.tools.pgpencryption.sys;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;

import javax.inject.Inject;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.util.encoders.Hex;

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
        return exec(keyTool.convertToPublicKey(keyFile));
    }

    public String withKey(Key publicKey) throws IOException, InvalidCipherTextException {
        return exec(keyTool.convertToPublicKey(publicKey));
    }

    private String exec(CipherParameters cipherParameters) throws IOException, InvalidCipherTextException {
        PKCS1Encoding encoding = new PKCS1Encoding(new RSAEngine());
        encoding.init(true, cipherParameters);

        int bufferSize = encoding.getInputBlockSize();

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        byte[][] chunks = Tools.chunkArray(readableText, bufferSize);
        for (byte[] oneChunk : chunks) {
            byte[] encryptedData = encoding.processBlock(oneChunk, 0, Math.min(bufferSize, oneChunk.length));
            Hex.encode(encryptedData, outputStream);
        }

        outputStream.flush();
        return outputStream.toString(StandardCharsets.UTF_8.name());
    }

}
