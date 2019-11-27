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
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.encoders.Hex;
import org.plytimebandit.tools.pgpencryption.util.ProcessLogger;
import org.plytimebandit.tools.pgpencryption.util.Tools;

public class PgpEncryptor extends AbstractPgpEncryptorDecryptor {

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

    public byte[] withKey(File keyFile) throws IOException {
        return exec(keyTool.convertToPublicKey(keyFile));
    }

    public byte[] withKey(Key publicKey) throws IOException {
        return exec(keyTool.convertToPublicKey(publicKey));
    }

    private byte[] exec(CipherParameters cipherParameters) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        int bufferSize = getCipherForEncryption(cipherParameters).getInputBlockSize();
        byte[][] chunks = Tools.chunkArray(readableText, bufferSize);
        ProcessLogger processLogger = new ProcessLogger(LOGGER, "Encryption", chunks.length);
        Arrays.stream(chunks).parallel()
                .map(bytes -> processBytes(bytes, getCipherForEncryption(cipherParameters), processLogger::logNextStep))
                .map(Hex::encode)
                .collect(Collectors.toList())
                .forEach(bytes -> writeBytes(outputStream, bytes));
        processLogger.logFinished();

        outputStream.flush();
        return outputStream.toByteArray();
    }

}
