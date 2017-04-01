package org.plytimebandit.tools.pgpencryption;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.assertj.core.api.Assertions;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.plytimebandit.tools.pgpencryption.sys.KeyTool;
import org.plytimebandit.tools.pgpencryption.sys.PgpDecryptor;
import org.plytimebandit.tools.pgpencryption.sys.PgpEncryptor;

import com.google.inject.Guice;
import com.google.inject.Injector;

public class PgpEncryptionTest {

    private PgpDecryptor pgpDecryptor;
    private PgpEncryptor pgpEncryptor;
    private KeyTool keyTool;

    @Before
    public void setUp() throws Exception {
        Injector injector = Guice.createInjector(new AppModule());
        pgpDecryptor = injector.getInstance(PgpDecryptor.class);
        pgpEncryptor = injector.getInstance(PgpEncryptor.class);
        keyTool = injector.getInstance(KeyTool.class);
    }

    @Test
    public void testKeyAlgorithmAndLength() throws Exception {
        KeyPair keyPair = keyTool.createKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        Assert.assertTrue(publicKey instanceof RSAKey);
        Assert.assertTrue(privateKey instanceof RSAKey);

        Assert.assertEquals("RSA", publicKey.getAlgorithm());
        Assert.assertEquals("RSA", privateKey.getAlgorithm());

        Assert.assertEquals(4096, ((RSAKey) publicKey).getModulus().bitLength());
        Assert.assertEquals(4096, ((RSAKey) privateKey).getModulus().bitLength());
    }

    @Test
    public void testUseKeysStoredInFiles() throws Exception {
        KeyPair keyPair = keyTool.createKeyPair();
        File publicKeyFile = writePublicKeyToFile(keyPair);
        File privateKeyFile = writePrivateKeyToFile(keyPair);

        String readableText = "This is a text that will be encrpyted and decrypted.";

        String encryptedString = pgpEncryptor.encrypt(readableText).withKey(publicKeyFile);
        String decryptedString = pgpDecryptor.decrypt(encryptedString).withKey(privateKeyFile);

        Assertions.assertThat(readableText).isNotEqualTo(encryptedString);
        Assertions.assertThat(encryptedString).isNotEqualTo(decryptedString);
        Assertions.assertThat(readableText).isEqualTo(decryptedString);
    }

    @Test
    public void testEncryptionDecryptionEqualsInputAndOutput() throws Exception {
        String readableText = "This is a text that will be encrpyted and decrypted.";

        KeyPair keyPair = keyTool.createKeyPair();
        String encryptedText = pgpEncryptor.encrypt(readableText).withKey(keyPair.getPublic());
        String decryptedText = pgpDecryptor.decrypt(encryptedText).withKey(keyPair.getPrivate());

        Assertions.assertThat(decryptedText).isEqualTo(readableText);
    }

    @Test
    public void testSequentialCreatedKeysAreNotEquals() throws Exception {
        KeyPair keyPair1 = keyTool.createKeyPair();
        KeyPair keyPair2 = keyTool.createKeyPair();

        Assertions.assertThat(keyTool.getPrivateKey(keyPair1)).isNotEqualTo(keyTool.getPrivateKey(keyPair2));
        Assertions.assertThat(keyTool.getPublicKey(keyPair1)).isNotEqualTo(keyTool.getPublicKey(keyPair2));
    }

    @Test
    public void testHexEncodingDecoding() throws Exception {
        String testString = "this is a string";

        String dataInHex = Hex.encodeHexString(testString.getBytes());
        String actual = new String(Hex.decodeHex(dataInHex.toCharArray()));

        Assertions.assertThat(actual).isEqualTo(testString);
        Assertions.assertThat(dataInHex).isNotEqualTo(actual);
        Assertions.assertThat(dataInHex).isNotEqualTo(testString);
    }

    @Test
    public void testRealFileWithBigBlockSizeEncryptionDecryption() throws Exception {
        File file = new File(getClass().getResource("test.txt").toURI());

        KeyPair keyPair = keyTool.createKeyPair();

        String encryptedData = pgpEncryptor.encrypt(file).withKey(keyPair.getPublic());
        String decryptedData = pgpDecryptor.decrypt(encryptedData).withKey(keyPair.getPrivate());

        String fileContent = FileUtils.readFileToString(file, StandardCharsets.UTF_8);

        Assert.assertEquals(decryptedData, fileContent);
        Assert.assertNotEquals(encryptedData, fileContent);
        Assert.assertNotEquals(encryptedData, decryptedData);
    }

    private File writePrivateKeyToFile(KeyPair keyPair) throws IOException {
        String privateKey = keyTool.getPrivateKey(keyPair);

        File tempFile = File.createTempFile("temp_pgp_private_test_", ".txt");
        tempFile.deleteOnExit();

        try (BufferedWriter writer = Files.newBufferedWriter(tempFile.toPath(), StandardCharsets.UTF_8, StandardOpenOption.WRITE)) {
            writer.write(privateKey);
            writer.flush();
        }

        return tempFile;
    }

    private File writePublicKeyToFile(KeyPair keyPair) throws IOException {
        String publicKey = keyTool.getPublicKey(keyPair);

        File tempFile = File.createTempFile("temp_pgp_public_test_", ".txt");
        tempFile.deleteOnExit();

        try (BufferedWriter writer = Files.newBufferedWriter(tempFile.toPath(), StandardCharsets.UTF_8, StandardOpenOption.WRITE)) {
            writer.write(publicKey);
            writer.flush();
        }

        return tempFile;
    }
}