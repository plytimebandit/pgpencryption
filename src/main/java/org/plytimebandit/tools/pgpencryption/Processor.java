package org.plytimebandit.tools.pgpencryption;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;

import javax.inject.Inject;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.CryptoException;
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

    void createKeys(String outputPath) throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
        if (doOutputFilesExist(outputPath)) {
            LOGGER.error(String.format(
                    "At least one of these files exist in output folder %s: %s, %s. Keys cannot be created.",
                    outputPath, PGP_KEY, PGP_PUB));
            return;
        }

        if (!createOutputPathIfNotExist(outputPath)) {
            return;
        }

        LOGGER.info("Creating key pair...");
        KeyPair keyPair = keyTool.createKeyPair();
        LOGGER.info("Done.");

        Path path = Paths.get(outputPath, PGP_PUB);
        LOGGER.info(String.format("Writing public key to file '%s'...", path));
        writeToFile(keyTool.convertPublicKeyToString(keyPair), path);
        LOGGER.info("Done.");

        path = Paths.get(outputPath, PGP_KEY);
        LOGGER.info(String.format("Writing private key to file '%s'...", path));
        writeToFile(keyTool.convertPrivateKeyToString(keyPair), path);
        LOGGER.info("Done.");
    }

    private boolean createOutputPathIfNotExist(String outputPath) {
        File outputDir = new File(outputPath);
        if (!outputDir.exists()) {
            boolean success = outputDir.mkdir();
            if (!success) {
                LOGGER.error(String.format("Cannot create output directory '%s'", outputDir));
            }
            return success;
        }
        return true;
    }

    void encryptFile(String key, String file) throws IOException, InvalidCipherTextException {
        File keyFile = new File(key);
        if (!keyFile.exists()) {
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
        byte[] encryptedData = pgpEncryptor.encrypt(new File(file)).withKey(keyFile);

        LOGGER.info(String.format("Writing output file %s...", file + ".enc"));
        writeToFile(encryptedData, Paths.get(file + ".enc"));

        LOGGER.info("Done.");
    }

    void encryptFile(String alias, String file, String keyStorePath, char[] password)
            throws IOException, GeneralSecurityException, DecoderException, CryptoException {
        File keyStoreFile = new File(keyStorePath);
        if (!keyStoreFile.exists()) {
            LOGGER.error(String.format("Key Store %s does not exist.", keyStorePath));
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

        PublicKey publicKey = keyTool.getPublicKeyFromKeyStore(keyStoreFile, alias, password);

        LOGGER.info(String.format("Encrypting file %s...", file));
        byte[] encryptedData = pgpEncryptor.encrypt(new File(file)).withKey(publicKey);

        LOGGER.info(String.format("Writing output file %s...", file + ".enc"));
        writeToFile(encryptedData, Paths.get(file + ".enc"));

        LOGGER.info("Done.");
    }

    void decryptFile(String key, String file) throws IOException, DecoderException, InvalidCipherTextException {
        File keyFile = new File(key);
        if (!keyFile.exists()) {
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
        byte[] decryptedData = pgpDecryptor.decrypt(new File(file)).withKey(keyFile);

        LOGGER.info(String.format("Writing output file %s...", file + ".dec"));
        writeToFile(decryptedData, Paths.get(file + ".dec"));

        LOGGER.info("Done.");
    }

    void decryptFile(String alias, String file, String keyStorePath, char[] password)
            throws IOException, GeneralSecurityException, DecoderException, CryptoException {
        File keyStoreFile = new File(keyStorePath);
        if (!keyStoreFile.exists()) {
            LOGGER.error(String.format("Key Store %s does not exist.", keyStorePath));
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

        Key privateKey = keyTool.getPrivateKeyFromKeyStore(keyStoreFile, alias, password);

        LOGGER.info(String.format("Decrypting file %s...", file));
        byte[] decryptedData = pgpDecryptor.decrypt(new File(file)).withKey(privateKey);

        LOGGER.info(String.format("Writing output file %s...", file + ".dec"));
        writeToFile(decryptedData, Paths.get(file + ".dec"));

        LOGGER.info("Done.");
    }

    private boolean doOutputFilesExist(String outputPath) {
        return new File(outputPath, PGP_PUB).exists() || new File(outputPath, PGP_KEY).exists();
    }

    private static void writeToFile(byte[] source, Path target) throws IOException {
        FileUtils.writeByteArrayToFile(target.toFile(), source);
    }

    private static void writeToFile(String source, Path target) throws IOException {
        FileUtils.writeStringToFile(target.toFile(), source, StandardCharsets.UTF_8);
    }
}
