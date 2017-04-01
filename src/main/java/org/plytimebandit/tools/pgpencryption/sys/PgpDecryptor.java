package org.plytimebandit.tools.pgpencryption.sys;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;

import javax.inject.Inject;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
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
        this.encryptedText = FileUtils.readFileToByteArray(encryptedText);
        return this;
    }

    public String withKey(File keyFile) throws IOException, DecoderException, InvalidCipherTextException {
        String key = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
        return exec(key);
    }

    public String withKey(Key privateKey) throws DecoderException, IOException, InvalidCipherTextException {
        return exec(keyTool.encodeKeyBase64(privateKey));
    }

    private String exec(String privateKeyString) throws IOException, InvalidCipherTextException, DecoderException {
        AsymmetricKeyParameter privateKey = keyTool.decodePrivateKeyBase64(privateKeyString);

        PKCS1Encoding encoding = new PKCS1Encoding(new RSAEngine());
        encoding.init(false, privateKey);

        int bufferSize = encoding.getInputBlockSize();

        StringBuilder result = new StringBuilder();

        byte[][] chunks = Tools.chunkArray(encryptedText, bufferSize);
        for (byte[] oneChunk : chunks) {
            byte[] decryptedData = encoding.processBlock(oneChunk, 0, oneChunk.length);
            result.append(new String(decryptedData, StandardCharsets.UTF_8));
        }

        return result.toString();
    }

}
