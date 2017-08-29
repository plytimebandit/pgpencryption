package org.plytimebandit.tools.pgpencryption;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import java.util.Collections;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.assertj.core.api.Assertions;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.plytimebandit.tools.pgpencryption.sys.KeyTool;
import org.plytimebandit.tools.pgpencryption.sys.PgpDecryptor;
import org.plytimebandit.tools.pgpencryption.sys.PgpEncryptor;

import com.google.inject.Guice;
import com.google.inject.Injector;

public class PgpEncryptionTest {

    private static final String TEXT = "This is a text that will be encrypted and decrypted.";

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

        String encryptedString = pgpEncryptor.encrypt(TEXT).withKey(publicKeyFile);
        String decryptedString = pgpDecryptor.decrypt(encryptedString).withKey(privateKeyFile);

        Assertions.assertThat(TEXT).isNotEqualTo(encryptedString);
        Assertions.assertThat(encryptedString).isNotEqualTo(decryptedString);
        Assertions.assertThat(TEXT).isEqualTo(decryptedString);
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

        Assertions.assertThat(keyTool.convertPrivateKeyToString(keyPair1)).isNotEqualTo(keyTool.convertPrivateKeyToString(keyPair2));
        Assertions.assertThat(keyTool.convertPublicKeyToString(keyPair1)).isNotEqualTo(keyTool.convertPublicKeyToString(keyPair2));
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
    public void testByteReadAndWriteOfPdfFile() throws Exception {
        File file = new File(getClass().getResource("test.pdf").toURI());
        File outputFile = File.createTempFile("temp_pgp_test_", ".pdf");
        outputFile.deleteOnExit();

        byte[] fileBytes = FileUtils.readFileToByteArray(file);
        FileUtils.writeByteArrayToFile(outputFile, fileBytes);

        Assertions.assertThat(outputFile.length()).isEqualTo(file.length());
        Assertions.assertThat(FileUtils.contentEquals(outputFile, file)).isTrue();
    }

    @Test
    public void testHexEncodingDecodingOfPdfFile() throws Exception {
        File file = new File(getClass().getResource("test.pdf").toURI());
        File outputFile = File.createTempFile("temp_pgp_test_", ".pdf");
        outputFile.deleteOnExit();

        byte[] fileBytes = FileUtils.readFileToByteArray(file);
        byte[] encodedFileBytes = org.bouncycastle.util.encoders.Hex.encode(fileBytes);
        String encodedFileString = new String(encodedFileBytes, StandardCharsets.UTF_8);

        byte[] fileBytesDecoded = org.bouncycastle.util.encoders.Hex.decode(encodedFileString.getBytes(StandardCharsets.UTF_8));

        FileUtils.writeByteArrayToFile(outputFile, fileBytesDecoded);

        Assertions.assertThat(outputFile.length()).isEqualTo(file.length());
        Assertions.assertThat(FileUtils.contentEquals(outputFile, file)).isTrue();
    }

    @Test
    public void testEncryptionAndDecryptionOfFileContentWithBigBlockSize() throws Exception {
        File file = new File(getClass().getResource("test.txt").toURI());

        KeyPair keyPair = keyTool.createKeyPair();

        String encryptedData = pgpEncryptor.encrypt(file).withKey(keyPair.getPublic());
        String decryptedData = pgpDecryptor.decrypt(encryptedData).withKey(keyPair.getPrivate());

        String fileContent = FileUtils.readFileToString(file, StandardCharsets.UTF_8);

        Assert.assertEquals(decryptedData, fileContent);
        Assert.assertNotEquals(encryptedData, fileContent);
        Assert.assertNotEquals(encryptedData, decryptedData);
    }

    @Test
    public void testEncryptionAndDecryptionOfPdfFile() throws Exception {
        File file = new File(getClass().getResource("test.pdf").toURI());

        KeyPair keyPair = keyTool.createKeyPair();

        String encryptedData = pgpEncryptor.encrypt(file).withKey(keyPair.getPublic());
        String decryptedData = pgpDecryptor.decrypt(encryptedData).withKey(keyPair.getPrivate());

        File outputFileDecrypted = File.createTempFile("temp_pgp_test_dec_", ".pdf");
        outputFileDecrypted.deleteOnExit();
        FileUtils.writeStringToFile(outputFileDecrypted, decryptedData, StandardCharsets.UTF_8);

        File outputFileEncrypted = File.createTempFile("temp_pgp_test_enc_", ".pdf");
        outputFileEncrypted.deleteOnExit();
        FileUtils.writeStringToFile(outputFileEncrypted, encryptedData, StandardCharsets.UTF_8);

        Assert.assertTrue(FileUtils.contentEqualsIgnoreEOL(file, outputFileDecrypted, StandardCharsets.UTF_8.name())); // TODO FileUtils.contentEquals() returns false!
    }

    @Test
    public void testEncryptionAndDecryptionUsingFilesWithKeyStore() throws Exception {
        File tempFile = File.createTempFile("temp_pgp_test_", ".txt");
        tempFile.deleteOnExit();
        File tempFileEnc = File.createTempFile("temp_pgp_enc_test_", ".txt");
        tempFileEnc.deleteOnExit();

        KeyStore keyStore = loadAndGetTestKeyStore();
        PublicKey publicKey = getPublicKey(keyStore);
        Key privateKey = getPrivateKey(keyStore);

        FileUtils.writeStringToFile(tempFile, TEXT, StandardCharsets.UTF_8);
        String encryptedData = pgpEncryptor.encrypt(tempFile).withKey(publicKey);

        FileUtils.writeStringToFile(tempFileEnc, encryptedData, StandardCharsets.UTF_8);
        String decryptedData = pgpDecryptor.decrypt(tempFileEnc).withKey(privateKey);

        Assert.assertEquals(TEXT, decryptedData);
    }

    @Test
    public void testKeyStore() throws Exception {
        KeyStore keyStore = loadAndGetTestKeyStore();
        Key privateKey = getPrivateKey(keyStore);
        PublicKey publicKey = getPublicKey(keyStore);

        String encrypted = pgpEncryptor.encrypt(TEXT).withKey(publicKey);
        String decryptedKey = pgpDecryptor.decrypt(encrypted).withKey(privateKey);

        Assert.assertEquals(TEXT, decryptedKey);
    }

    @Test
    public void testStartParametersEmpty() throws Exception {
        PgpEncryption pgpEncryptionSpy = createPgpEncryptionSpy();

        pgpEncryptionSpy.process(Collections.emptyList());

        Mockito.verify(pgpEncryptionSpy).printUsage();
    }

    @Test
    public void testStartParametersNull() throws Exception {
        PgpEncryption pgpEncryptionSpy = createPgpEncryptionSpy();

        pgpEncryptionSpy.process(null);

        Mockito.verify(pgpEncryptionSpy).printUsage();
    }

    @Test
    public void testStartParametersCreateKeys() throws Exception {
        Processor processorMock = Mockito.mock(Processor.class);
        PgpEncryption pgpEncryptionSpy = createPgpEncryptionSpy(processorMock);

        pgpEncryptionSpy.process(Arrays.asList("-c", "output"));

        Mockito.verify(pgpEncryptionSpy, Mockito.times(0)).printUsage();
        Mockito.verify(processorMock).createKeys(ArgumentMatchers.anyString());
    }

    @Test
    public void testStartParametersEncrypt() throws Exception {
        Processor processorMock = Mockito.mock(Processor.class);
        PgpEncryption pgpEncryptionSpy = createPgpEncryptionSpy(processorMock);

        pgpEncryptionSpy.process(Arrays.asList("-e", "key", "-f", "file"));

        Mockito.verify(pgpEncryptionSpy, Mockito.times(0)).printUsage();
        Mockito.verify(processorMock).encryptFile(ArgumentMatchers.anyString(), ArgumentMatchers.anyString());
    }

    @Test
    public void testStartParametersDecrypt() throws Exception {
        Processor processorMock = Mockito.mock(Processor.class);
        PgpEncryption pgpEncryptionSpy = createPgpEncryptionSpy(processorMock);

        pgpEncryptionSpy.process(Arrays.asList("-d", "key", "-f", "file"));

        Mockito.verify(pgpEncryptionSpy, Mockito.times(0)).printUsage();
        Mockito.verify(processorMock).decryptFile(ArgumentMatchers.anyString(), ArgumentMatchers.anyString());
    }

    private PgpEncryption createPgpEncryptionSpy() throws Exception {
        return createPgpEncryptionSpy(createProcessorMock());
    }

    private PgpEncryption createPgpEncryptionSpy(Processor processorMock) {
        PgpEncryption pgpEncryptionSpy = Mockito.spy(new PgpEncryption(processorMock));
        Mockito.doNothing().when(pgpEncryptionSpy).printUsage();

        return pgpEncryptionSpy;
    }

    private Processor createProcessorMock() throws Exception {
        Processor processorMock = Mockito.mock(Processor.class);
        Mockito.doNothing().when(processorMock).createKeys(ArgumentMatchers.anyString());
        Mockito.doNothing().when(processorMock).encryptFile(ArgumentMatchers.anyString(), ArgumentMatchers.anyString());
        Mockito.doNothing().when(processorMock).decryptFile(ArgumentMatchers.anyString(), ArgumentMatchers.anyString());
        return processorMock;
    }

    private File writePrivateKeyToFile(KeyPair keyPair) throws IOException {
        String privateKey = keyTool.convertPrivateKeyToString(keyPair);

        File tempFile = File.createTempFile("temp_pgp_private_test_", ".txt");
        tempFile.deleteOnExit();

        try (BufferedWriter writer = Files.newBufferedWriter(tempFile.toPath(), StandardCharsets.UTF_8, StandardOpenOption.WRITE)) {
            writer.write(privateKey);
            writer.flush();
        }

        return tempFile;
    }

    private File writePublicKeyToFile(KeyPair keyPair) throws IOException {
        String publicKey = keyTool.convertPublicKeyToString(keyPair);

        File tempFile = File.createTempFile("temp_pgp_public_test_", ".txt");
        tempFile.deleteOnExit();

        try (BufferedWriter writer = Files.newBufferedWriter(tempFile.toPath(), StandardCharsets.UTF_8, StandardOpenOption.WRITE)) {
            writer.write(publicKey);
            writer.flush();
        }

        return tempFile;
    }

    private PublicKey getPublicKey(KeyStore keyStore) throws KeyStoreException {
        Certificate certificate = keyStore.getCertificate("test");
        return certificate.getPublicKey();
    }

    private Key getPrivateKey(KeyStore keyStore) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return keyStore.getKey("test", "test123".toCharArray());
    }

    private KeyStore loadAndGetTestKeyStore() throws URISyntaxException, KeyStoreException, NoSuchProviderException, IOException, NoSuchAlgorithmException, CertificateException {
        File keyStoreFile = new File(getClass().getResource("testkeystore.jks").toURI());

        KeyStore keyStore = KeyStore.getInstance("JKS", "SUN");
        keyStore.load(new FileInputStream(keyStoreFile), "test123".toCharArray());
        return keyStore;
    }
}