package org.plytimebandit.tools.pgpencryption.sys;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.Key;
import java.util.Arrays;
import java.util.stream.Collectors;

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
import org.plytimebandit.tools.pgpencryption.util.ProcessLogger;
import org.plytimebandit.tools.pgpencryption.util.Tools;

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
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        int bufferSize = getCipher(cipherParameters).getInputBlockSize();
        byte[][] chunks = Tools.chunkArray(readableText, bufferSize);
        ProcessLogger processLogger = new ProcessLogger(LOGGER, chunks.length);
        Arrays.stream(chunks).parallel()
                .map(bytes -> processBytes(bytes, cipherParameters, processLogger))
                .collect(Collectors.toList())
                .forEach(bytes -> writeBytes(outputStream, bytes));
        LOGGER.info("Encryption finished.");

        outputStream.flush();
        return outputStream.toByteArray();
    }

    private byte[] processBytes(byte[] bytes, CipherParameters cipherParameters, ProcessLogger processLogger) {
        BufferedAsymmetricBlockCipher cipher = getCipher(cipherParameters);
        cipher.processBytes(bytes, 0, bytes.length);
        try {
            processLogger.logNextStep("Encryption");
            return cipher.doFinal();
        } catch (InvalidCipherTextException e) {
            LOGGER.error(e);
            return new byte[0];
        }
    }

    private void writeBytes(ByteArrayOutputStream outputStream, byte[] bytes) {
        try {
            Hex.encode(bytes, outputStream);
        } catch (IOException e) {
            LOGGER.error(e);
        }
    }

    private BufferedAsymmetricBlockCipher getCipher(CipherParameters cipherParameters) {
        PKCS1Encoding encoding = new PKCS1Encoding(new RSAEngine());
        BufferedAsymmetricBlockCipher cipher = new BufferedAsymmetricBlockCipher(encoding);
        cipher.init(true, cipherParameters);
        return cipher;
    }
}
