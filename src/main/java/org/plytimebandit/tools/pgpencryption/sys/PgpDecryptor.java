package org.plytimebandit.tools.pgpencryption.sys;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;

import javax.inject.Inject;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.util.encoders.Hex;

public class PgpDecryptor {

    private final KeyTool keyTool;

    private byte[] encryptedText;

    @Inject
    public PgpDecryptor(KeyTool keyTool) {
        this.keyTool = keyTool;
    }

    public PgpDecryptor decrypt(String encryptedText) {
        this.encryptedText = Hex.decode(encryptedText);
        return this;
    }

    public PgpDecryptor decrypt(File encryptedText) throws IOException {
        this.encryptedText = Hex.decode(FileUtils.readFileToByteArray(encryptedText));
        return this;
    }

    public String withKey(File keyFile) throws IOException, DecoderException, InvalidCipherTextException {
        return exec(keyTool.convertToPrivateKey(keyFile));
    }

    public String withKey(Key privateKey) throws DecoderException, IOException, InvalidCipherTextException {
        return exec(keyTool.convertToPrivateKey(privateKey));
    }

    private String exec(CipherParameters cipherParameters) throws IOException, InvalidCipherTextException, DecoderException {
        PKCS1Encoding encoding = new PKCS1Encoding(new RSAEngine());
        encoding.init(false, cipherParameters);

        int bufferSize = encoding.getInputBlockSize();

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        byte[][] chunks = Tools.chunkArray(encryptedText, bufferSize);
        for (byte[] oneChunk : chunks) {
            byte[] decryptedData = encoding.processBlock(oneChunk, 0, oneChunk.length);
            byteArrayOutputStream.write(decryptedData);
        }

        byteArrayOutputStream.flush();
        return byteArrayOutputStream.toString(StandardCharsets.UTF_8.name());
    }

}
