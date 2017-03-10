package org.plytimebandit.tools.pgpencryption;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.inject.Inject;

import org.apache.commons.codec.DecoderException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.plytimebandit.tools.pgpencryption.sys.KeyTool;
import org.plytimebandit.tools.pgpencryption.sys.PgpDecryptor;
import org.plytimebandit.tools.pgpencryption.sys.PgpEncryptor;

class Processor {

    private static final Logger LOGGER = LogManager.getLogger(Processor.class);

    private static final String PGP_PUB = "pgp.pub";
    private static final String PGP_KEY = "pgp.key";

    private final KeyTool keyTool;
    private final PgpDecryptor pgpDecryptor;
    private final PgpEncryptor pgpEncryptor;

    @Inject
    public Processor(KeyTool keyTool, PgpDecryptor pgpDecryptor, PgpEncryptor pgpEncryptor) {
        this.keyTool = keyTool;
        this.pgpDecryptor = pgpDecryptor;
        this.pgpEncryptor = pgpEncryptor;
    }

    void createKeys(String outputPath) throws NoSuchAlgorithmException, IOException {
        if (doOutputFilesExist(outputPath)) {
            LOGGER.error(String.format(
                    "At least one of these files exist in output folder %s: %s, %s. Keys cannot be created.",
                    outputPath, PGP_KEY, PGP_PUB));
            return;
        }

        KeyPair keyPair = keyTool.createKeyPair();

        Path path = Paths.get(outputPath, PGP_PUB);
        LOGGER.info(String.format("Writing public key to file '%s'...", path));
        writeToFile(keyTool.getPublicKey(keyPair), path);
        LOGGER.info("Done.");

        path = Paths.get(outputPath, PGP_KEY);
        LOGGER.info(String.format("Writing private key to file '%s'...", path));
        writeToFile(keyTool.getPrivateKey(keyPair), path);
        LOGGER.info("Done.");
    }

    void encryptFile(String key, String file) throws IOException, InvalidCipherTextException {
        if (!new File(key).exists()) {
            LOGGER.error(String.format("Key %s does not exist.", key));
            return;
        }
        if (!new File(file).exists()) {
            LOGGER.error(String.format("File %s does not exist.", file));
            return;
        }
        if (new File(file + ".enc").exists()) {
            LOGGER.error(String.format("File %s already exists.", file + ".enc"));
            return;
        }

        LOGGER.info(String.format("Encrypting file %s...", file));
        String encryptedData = pgpEncryptor.encrypt(new File(file)).withKey(key);

        LOGGER.info(String.format("Writing output file %s...", file + ".enc"));
        writeToFile(encryptedData, Paths.get(file + ".enc"));

        LOGGER.info("Done.");
    }

    void decryptFile(String key, String file) throws IOException, DecoderException, InvalidCipherTextException {
        if (!new File(key).exists()) {
            LOGGER.error(String.format("Key %s does not exist.", key));
            return;
        }
        if (!new File(file).exists()) {
            LOGGER.error(String.format("File %s does not exist.", file));
            return;
        }
        if (new File(file + ".dec").exists()) {
            LOGGER.error(String.format("File %s already exists.", file + ".dec"));
            return;
        }

        LOGGER.info(String.format("Decrypting file %s...", file));
        String decryptedData = pgpDecryptor.decrypt(new File(file)).withKey(key);

        LOGGER.info(String.format("Writing output file %s...", file + ".dec"));
        writeToFile(decryptedData, Paths.get(file + ".dec"));

        LOGGER.info("Done.");
    }

    private boolean doOutputFilesExist(String outputPath) {
        return new File(outputPath, PGP_PUB).exists() || new File(outputPath, PGP_KEY).exists();
    }

    private static void writeToFile(String source, Path target) throws IOException {
        try (BufferedWriter writer = Files.newBufferedWriter(
                target, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            writer.write(source);
            writer.flush();
        }
    }
}
