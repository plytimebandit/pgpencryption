package org.plytimebandit.tools.pgpencryption.sys;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.BufferedAsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;

abstract class AbstractPgpEncryptorDecryptor {

    private static final Logger LOGGER = LogManager.getLogger(AbstractPgpEncryptorDecryptor.class);

    BufferedAsymmetricBlockCipher getCipherForEncryption(CipherParameters cipherParameters) {
        return getCipher(cipherParameters, true);
    }

    BufferedAsymmetricBlockCipher getCipherForDecryption(CipherParameters cipherParameters) {
        return getCipher(cipherParameters, false);
    }

    private BufferedAsymmetricBlockCipher getCipher(CipherParameters cipherParameters, boolean forEncryption) {
        PKCS1Encoding encoding = new PKCS1Encoding(new RSAEngine());
        BufferedAsymmetricBlockCipher cipher = new BufferedAsymmetricBlockCipher(encoding);
        cipher.init(forEncryption, cipherParameters);
        return cipher;
    }

    byte[] processBytes(byte[] bytes, BufferedAsymmetricBlockCipher cipher, Runnable runnable) {
        cipher.processBytes(bytes, 0, bytes.length);
        try {
            runnable.run();
            return cipher.doFinal();
        } catch (InvalidCipherTextException e) {
            LOGGER.error(e);
            return new byte[0];
        }
    }

    void writeBytes(ByteArrayOutputStream outputStream, byte[] bytes) {
        try {
            outputStream.write(bytes);
        } catch (IOException e) {
            LOGGER.error(e);
        }
    }
}
