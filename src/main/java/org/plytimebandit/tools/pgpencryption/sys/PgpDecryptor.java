package org.plytimebandit.tools.pgpencryption.sys;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.Key;

import javax.inject.Inject;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.crypto.BufferedAsymmetricBlockCipher;
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

    public PgpDecryptor decrypt(byte[] encryptedText) {
        this.encryptedText = Hex.decode(encryptedText);
        return this;
    }

    public PgpDecryptor decrypt(File encryptedText) throws IOException {
        this.encryptedText = Hex.decode(FileUtils.readFileToByteArray(encryptedText));
        return this;
    }

    public byte[] withKey(File keyFile) throws IOException, DecoderException, InvalidCipherTextException {
        return exec(keyTool.convertToPrivateKey(keyFile));
    }

    public byte[] withKey(Key privateKey) throws DecoderException, IOException, InvalidCipherTextException {
        return exec(keyTool.convertToPrivateKey(privateKey));
    }

    private byte[] exec(CipherParameters cipherParameters) throws IOException, InvalidCipherTextException, DecoderException {
        PKCS1Encoding encoding = new PKCS1Encoding(new RSAEngine());
        BufferedAsymmetricBlockCipher cipher = new BufferedAsymmetricBlockCipher(encoding);
        cipher.init(false, cipherParameters);

        int bufferSize = encoding.getInputBlockSize();

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        byte[][] chunks = Tools.chunkArray(encryptedText, bufferSize);
        for (byte[] oneChunk : chunks) {
            cipher.processBytes(oneChunk, 0, oneChunk.length);
            outputStream.write(cipher.doFinal());
        }

        outputStream.flush();
        return outputStream.toByteArray();
    }

}
