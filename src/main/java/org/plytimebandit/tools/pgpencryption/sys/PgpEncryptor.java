package org.plytimebandit.tools.pgpencryption.sys;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.inject.Inject;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import com.google.common.collect.Lists;

public class PgpEncryptor {

    private final KeyTool keyTool;

    private String readableText;

    @Inject
    public PgpEncryptor(KeyTool keyTool) {
        this.keyTool = keyTool;
    }

    public PgpEncryptor encrypt(String readableText) {
        this.readableText = readableText;
        return this;
    }

    public PgpEncryptor encrypt(File readableText) throws IOException {
        this.readableText = FileUtils.readFileToString(readableText, StandardCharsets.UTF_8);
        return this;
    }

    public String withKey(String keyFile) throws IOException, InvalidCipherTextException {
        return withKey(new File(keyFile));
    }

    public String withKey(File keyFile) throws IOException, InvalidCipherTextException {
        String key = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
        return exec(key);
    }

    public String withKey(PublicKey publicKey) throws IOException, InvalidCipherTextException {
        return exec(keyTool.getPublicKey(publicKey));
    }

    private String exec(String publicKeyString) throws IOException, InvalidCipherTextException {
        AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(Base64.decodeBase64(publicKeyString));

        PKCS1Encoding encoding = new PKCS1Encoding(new RSAEngine());
        encoding.init(true, publicKey);

        byte[] readableTextBytes = readableText.getBytes(StandardCharsets.UTF_8);

        if (readableTextBytes.length <= encoding.getInputBlockSize()) {
            return execAllBytesAtOnce(encoding);
        } else {
            return execBytesInSingleSteps(encoding, readableTextBytes);
        }
    }

    private String execBytesInSingleSteps(PKCS1Encoding encoding, byte[] readableTextBytes) throws InvalidCipherTextException {
        int bufferSize = encoding.getInputBlockSize();

        Byte[] bytes = ArrayUtils.toObject(readableTextBytes);
        List<List<Byte>> partition = Lists.partition(Arrays.asList(bytes), bufferSize);

        List<Byte> result = new ArrayList<>();

        for (List<Byte> byteList : partition) {
            Byte[] objects = byteList.toArray(new Byte[byteList.size()]);
            byte[] hexEncodedCipher = encoding.processBlock(
                    ArrayUtils.toPrimitive(objects), 0, Math.min(bufferSize, byteList.size()));
            result.addAll(Arrays.asList(ArrayUtils.toObject(hexEncodedCipher)));
        }

        byte[] primitiveResult = ArrayUtils.toPrimitive(result.toArray(new Byte[result.size()]));
        return Hex.encodeHexString(primitiveResult);
    }

    private String execAllBytesAtOnce(PKCS1Encoding encoding) throws InvalidCipherTextException {
        byte[] hexEncodedCipher = encoding.processBlock(
                readableText.getBytes(StandardCharsets.UTF_8), 0, readableText.length());
        return Hex.encodeHexString(hexEncodedCipher);
    }

}
