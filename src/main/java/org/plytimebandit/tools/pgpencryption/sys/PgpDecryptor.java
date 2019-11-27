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

public class PgpDecryptor extends AbstractPgpEncryptorDecryptor {

    private static final Logger LOGGER = LogManager.getLogger(PgpDecryptor.class);

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

    public byte[] withKey(File keyFile) throws IOException {
        return exec(keyTool.convertToPrivateKey(keyFile));
    }

    public byte[] withKey(Key privateKey) throws IOException {
        return exec(keyTool.convertToPrivateKey(privateKey));
    }

    private byte[] exec(CipherParameters cipherParameters) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        int bufferSize = getCipherForDecryption(cipherParameters).getInputBlockSize();
        byte[][] chunks = Tools.chunkArray(encryptedText, bufferSize);
        ProcessLogger processLogger = new ProcessLogger(LOGGER, "Decryption", chunks.length);
        Arrays.stream(chunks).parallel()
                .map(bytes -> processBytes(bytes, getCipherForDecryption(cipherParameters), processLogger::logNextStep))
                .collect(Collectors.toList())
                .forEach(bytes -> writeBytes(outputStream, bytes));
        processLogger.logFinished();

        outputStream.flush();
        return outputStream.toByteArray();
    }

}
