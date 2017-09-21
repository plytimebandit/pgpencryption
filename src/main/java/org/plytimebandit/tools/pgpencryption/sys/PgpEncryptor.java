package org.plytimebandit.tools.pgpencryption.sys;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.Key;

import javax.inject.Inject;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.BufferedAsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.util.encoders.Hex;

public class PgpEncryptor {

    private static final Logger LOGGER = LogManager.getLogger(PgpEncryptor.class);

    private final KeyTool keyTool;

    private byte[] readableText;

    @Inject
    public PgpEncryptor(KeyTool keyTool) {
        this.keyTool = keyTool;
    }

    public PgpEncryptor encrypt(byte[] readableText) {
        this.readableText = readableText;
        return this;
    }

    public PgpEncryptor encrypt(File readableText) throws IOException {
        this.readableText = FileUtils.readFileToByteArray(readableText);
        return this;
    }

    public byte[] withKey(File keyFile) throws IOException, InvalidCipherTextException {
        return exec(keyTool.convertToPublicKey(keyFile));
    }

    public byte[] withKey(Key publicKey) throws IOException, InvalidCipherTextException {
        return exec(keyTool.convertToPublicKey(publicKey));
    }

    private byte[] exec(CipherParameters cipherParameters) throws IOException, InvalidCipherTextException {
        PKCS1Encoding encoding = new PKCS1Encoding(new RSAEngine());
        BufferedAsymmetricBlockCipher cipher = new BufferedAsymmetricBlockCipher(encoding);
        cipher.init(true, cipherParameters);

        int bufferSize = encoding.getInputBlockSize();

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        byte[][] chunks = Tools.chunkArray(readableText, bufferSize);
        ProcessLogger processLogger = new ProcessLogger(LOGGER, chunks.length);
        for (byte[] oneChunk : chunks) {
            processLogger.logNextStep("Encryption");
            cipher.processBytes(oneChunk, 0, Math.min(bufferSize, oneChunk.length));
            Hex.encode(cipher.doFinal(), outputStream);
        }
        LOGGER.info("Encryption finished.");

        outputStream.flush();
        return outputStream.toByteArray();
    }

}
