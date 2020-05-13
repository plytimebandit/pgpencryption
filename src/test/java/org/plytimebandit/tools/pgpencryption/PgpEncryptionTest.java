package org.plytimebandit.tools.pgpencryption;

import com.google.inject.Guice;
import com.google.inject.Injector;
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

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAKey;

public class PgpEncryptionTest {

    private static final String TEXT = "This is a text that will be encrypted and decrypted.";

    private PgpDecryptor pgpDecryptor;
    private PgpEncryptor pgpEncryptor;
    private KeyTool keyTool;

    @Before
    public void setUp() {
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

        byte[] encryptedString = pgpEncryptor.encrypt(TEXT.getBytes(StandardCharsets.UTF_8)).withKey(publicKeyFile);
        byte[] decryptedString = pgpDecryptor.decrypt(encryptedString).withKey(privateKeyFile);

        Assertions.assertThat(TEXT).isNotEqualTo(new String(encryptedString, StandardCharsets.UTF_8));
        Assertions.assertThat(encryptedString).isNotEqualTo(decryptedString);
        Assertions.assertThat(TEXT).isEqualTo(new String(decryptedString, StandardCharsets.UTF_8));
    }

    @Test
    public void testEncryptionDecryptionEqualsInputAndOutput() throws Exception {
        String readableText = "This is a text that will be encrpyted and decrypted.";

        KeyPair keyPair = keyTool.createKeyPair();
        byte[] encryptedText = pgpEncryptor.encrypt(readableText.getBytes(StandardCharsets.UTF_8)).withKey(keyPair.getPublic());
        byte[] decryptedText = pgpDecryptor.decrypt(encryptedText).withKey(keyPair.getPrivate());

        Assertions.assertThat(new String(decryptedText, StandardCharsets.UTF_8)).isEqualTo(readableText);
    }

    @Test
    public void testEncryptionDecryptionEqualsInputAndOutputWithByteKey() throws Exception {
        String readableText = "hello world!";

        KeyPair keyPair = keyTool.createKeyPair();
        byte[] pkBytes = keyTool.convertPublicKeyToBytes(keyPair);

        byte[] enc = pgpEncryptor
                .encrypt(readableText.getBytes(StandardCharsets.UTF_8))
                .withKey(pkBytes);
        byte[] dec = pgpDecryptor
                .decrypt(enc)
                .withKey(keyPair.getPrivate());

        Assertions.assertThat(new String(dec, StandardCharsets.UTF_8)).isEqualTo(readableText);
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

        byte[] encryptedData = pgpEncryptor.encrypt(file).withKey(keyPair.getPublic());
        byte[] decryptedData = pgpDecryptor.decrypt(encryptedData).withKey(keyPair.getPrivate());

        byte[] fileContent = FileUtils.readFileToByteArray(file);

        Assert.assertArrayEquals(decryptedData, fileContent);
        Assert.assertNotEquals(encryptedData, fileContent);
        Assert.assertNotEquals(encryptedData, decryptedData);
    }

    @Test
    public void testEncryptionAndDecryptionOfPdfFile() throws Exception {
        File file = new File(getClass().getResource("test.pdf").toURI());

        KeyPair keyPair = keyTool.createKeyPair();

        byte[] encryptedData = pgpEncryptor.encrypt(file).withKey(keyPair.getPublic());
        byte[] decryptedData = pgpDecryptor.decrypt(encryptedData).withKey(keyPair.getPrivate());

        File outputFileEncrypted = File.createTempFile("temp_pgp_test_enc_", ".pdf");
        outputFileEncrypted.deleteOnExit();
        FileUtils.writeByteArrayToFile(outputFileEncrypted, encryptedData);

        File outputFileDecrypted = File.createTempFile("temp_pgp_test_dec_", ".pdf");
        outputFileDecrypted.deleteOnExit();
        FileUtils.writeByteArrayToFile(outputFileDecrypted, decryptedData);

        Assert.assertTrue(FileUtils.contentEquals(file, outputFileDecrypted));
    }

    @Test
    public void testEncryptionAndDecryptionOfPdfFile2() throws Exception {
        File file = new File(getClass().getResource("test2.pdf").toURI());

        KeyPair keyPair = keyTool.createKeyPair();

        byte[] encryptedData = pgpEncryptor.encrypt(file).withKey(keyPair.getPublic());
        byte[] decryptedData = pgpDecryptor.decrypt(encryptedData).withKey(keyPair.getPrivate());

        File outputFileEncrypted = File.createTempFile("temp_pgp_test_enc_", ".pdf");
        outputFileEncrypted.deleteOnExit();
        FileUtils.writeByteArrayToFile(outputFileEncrypted, encryptedData);

        File outputFileDecrypted = File.createTempFile("temp_pgp_test_dec_", ".pdf");
        outputFileDecrypted.deleteOnExit();
        FileUtils.writeByteArrayToFile(outputFileDecrypted, decryptedData);

        Assert.assertTrue(FileUtils.contentEquals(file, outputFileDecrypted));
    }

    @Test
    public void testEncryptionAndDecryptionOfFileWithKeyStore() throws Exception {
        File tempFile = File.createTempFile("temp_pgp_test_", ".txt");
        tempFile.deleteOnExit();
        File tempFileEnc = File.createTempFile("temp_pgp_enc_test_", ".txt");
        tempFileEnc.deleteOnExit();

        KeyStore keyStore = loadAndGetTestKeyStore();
        PublicKey publicKey = getPublicKey(keyStore);
        Key privateKey = getPrivateKey(keyStore);

        FileUtils.writeStringToFile(tempFile, TEXT, StandardCharsets.UTF_8);
        byte[] encryptedData = pgpEncryptor.encrypt(tempFile).withKey(publicKey);

        FileUtils.writeByteArrayToFile(tempFileEnc, encryptedData);
        byte[] decryptedData = pgpDecryptor.decrypt(tempFileEnc).withKey(privateKey);

        Assert.assertEquals(TEXT, new String(decryptedData, StandardCharsets.UTF_8));
    }

    @Test
    public void testEncryptionAndDecryptionOfStringWithKeyStore() throws Exception {
        KeyStore keyStore = loadAndGetTestKeyStore();
        Key privateKey = getPrivateKey(keyStore);
        PublicKey publicKey = getPublicKey(keyStore);

        byte[] encrypted = pgpEncryptor.encrypt(TEXT.getBytes(StandardCharsets.UTF_8)).withKey(publicKey);
        byte[] decryptedKey = pgpDecryptor.decrypt(encrypted).withKey(privateKey);

        Assert.assertEquals(TEXT, new String(decryptedKey, StandardCharsets.UTF_8));
    }

    @Test
    public void testStartParametersEmpty() throws Exception {
        PgpEncryption pgpEncryptionSpy = createPgpEncryptionSpy();

        String[] emptyArray = {};
        pgpEncryptionSpy.parseArgsAndExecute(emptyArray);

        Mockito.verify(pgpEncryptionSpy).printUsage();
    }

    @Test
    public void testStartParametersNotExclusively() throws Exception {
        PgpEncryption pgpEncryptionSpy = createPgpEncryptionSpy();

        pgpEncryptionSpy.parseArgsAndExecute("-c", "x", "-e", "y");

        Mockito.verify(pgpEncryptionSpy).printUsage();
    }

    @Test
    public void testStartParametersCreateKeys() throws Exception {
        Processor processorMock = Mockito.mock(Processor.class);
        PgpEncryption pgpEncryptionSpy = createPgpEncryptionSpy(processorMock);

        pgpEncryptionSpy.parseArgsAndExecute("-c", "output");

        Mockito.verify(pgpEncryptionSpy, Mockito.never()).printUsage();
        Mockito.verify(processorMock).createKeys(ArgumentMatchers.anyString());
    }

    @Test
    public void testStartParametersEncrypt() throws Exception {
        Processor processorMock = Mockito.mock(Processor.class);
        PgpEncryption pgpEncryptionSpy = createPgpEncryptionSpy(processorMock);

        pgpEncryptionSpy.parseArgsAndExecute("-e", "key", "-f", "file");

        Mockito.verify(pgpEncryptionSpy, Mockito.never()).printUsage();
        Mockito.verify(processorMock).encryptFile(ArgumentMatchers.anyString(), ArgumentMatchers.anyString());
    }

    @Test
    public void testStartParametersDecrypt() throws Exception {
        Processor processorMock = Mockito.mock(Processor.class);
        PgpEncryption pgpEncryptionSpy = createPgpEncryptionSpy(processorMock);

        pgpEncryptionSpy.parseArgsAndExecute("-d", "key", "-f", "file");

        Mockito.verify(pgpEncryptionSpy, Mockito.never()).printUsage();
        Mockito.verify(processorMock).decryptFile(ArgumentMatchers.anyString(), ArgumentMatchers.anyString());
    }

    @Test
    public void testStartParametersEncryptWithKeyStore() throws Exception {
        Processor processorMock = Mockito.mock(Processor.class);
        PgpEncryption pgpEncryptionSpy = createPgpEncryptionSpy(processorMock);

        pgpEncryptionSpy.parseArgsAndExecute("-k", "keystore", "-e", "key", "-f", "file");

        Mockito.verify(pgpEncryptionSpy, Mockito.never()).printUsage();
        Mockito.verify(processorMock).encryptFile(ArgumentMatchers.anyString(), ArgumentMatchers.anyString(), ArgumentMatchers.anyString(), ArgumentMatchers.any());
    }

    @Test
    public void testStartParametersDecryptWithKeyStore() throws Exception {
        Processor processorMock = Mockito.mock(Processor.class);
        PgpEncryption pgpEncryptionSpy = createPgpEncryptionSpy(processorMock);

        pgpEncryptionSpy.parseArgsAndExecute("-k", "keystore", "-d", "key", "-f", "file");

        Mockito.verify(pgpEncryptionSpy, Mockito.never()).printUsage();
        Mockito.verify(processorMock).decryptFile(ArgumentMatchers.anyString(), ArgumentMatchers.anyString(), ArgumentMatchers.anyString(), ArgumentMatchers.any());
    }

    @Test
    public void testHelpParameter() {
        Processor processorMock = Mockito.mock(Processor.class);
        PgpEncryption pgpEncryptionSpy = createPgpEncryptionSpy(processorMock);

        pgpEncryptionSpy.parseArgsAndExecute("-h");

        Mockito.verify(pgpEncryptionSpy).printUsage();
    }

    private PgpEncryption createPgpEncryptionSpy() throws Exception {
        return createPgpEncryptionSpy(createProcessorMock());
    }

    private PgpEncryption createPgpEncryptionSpy(Processor processorMock) {
        PgpEncryption pgpEncryptionSpy = Mockito.spy(new PgpEncryption(processorMock));
        Mockito.doNothing().when(pgpEncryptionSpy).printUsage();
        Mockito.doAnswer(invocationOnMock -> new char[0]).when(pgpEncryptionSpy).readPassword();

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