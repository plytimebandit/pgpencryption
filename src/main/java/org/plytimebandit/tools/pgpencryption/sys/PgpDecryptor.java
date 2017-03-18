package org.plytimebandit.tools.pgpencryption.sys;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.List;

import javax.inject.Inject;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

import com.google.common.collect.Lists;

public class PgpDecryptor {

    private final KeyTool keyTool;

    private String encryptedText;

    @Inject
    public PgpDecryptor(KeyTool keyTool) {
        this.keyTool = keyTool;
    }

    public PgpDecryptor decrypt(String encryptedText) {
        this.encryptedText = encryptedText;
        return this;
    }

    public PgpDecryptor decrypt(File encryptedText) throws IOException {
        this.encryptedText = FileUtils.readFileToString(encryptedText, StandardCharsets.UTF_8);
        return this;
    }

    public String withKey(String keyFile) throws InvalidCipherTextException, IOException, DecoderException {
        return withKey(new File(keyFile));
    }

    public String withKey(File keyFile) throws IOException, DecoderException, InvalidCipherTextException {
        String key = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
        return exec(key);
    }

    public String withKey(PrivateKey privateKey) throws DecoderException, IOException, InvalidCipherTextException {
        return exec(keyTool.getPrivateKey(privateKey));
    }

    private String exec(String privateKeyString) throws IOException, InvalidCipherTextException, DecoderException {
        AsymmetricKeyParameter privateKey = PrivateKeyFactory.createKey(Base64.decodeBase64(privateKeyString));

        PKCS1Encoding encoding = new PKCS1Encoding(new RSAEngine());
        encoding.init(false, privateKey);

        byte[] messageBytes = Hex.decodeHex(encryptedText.toCharArray());
        int bufferSize = encoding.getInputBlockSize();


        if (messageBytes.length <= bufferSize) {
            byte[] decryptedData = encoding.processBlock(messageBytes, 0, messageBytes.length);
            return new String(decryptedData, StandardCharsets.UTF_8);

        } else {
            Byte[] bytes = ArrayUtils.toObject(messageBytes);
            List<List<Byte>> partition = Lists.partition(Arrays.asList(bytes), bufferSize);

            StringBuilder result = new StringBuilder();

            for (List<Byte> byteList : partition) {
                Byte[] objects = byteList.toArray(new Byte[byteList.size()]);
                byte[] decryptedData = encoding.processBlock(
                        ArrayUtils.toPrimitive(objects), 0, Math.min(bufferSize, byteList.size()));
                result.append(new String(decryptedData, StandardCharsets.UTF_8));
            }

            return result.toString();
        }
    }
}
