package org.plytimebandit.tools.pgpencryption;

import java.io.Console;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import javax.inject.Inject;

import org.apache.commons.collections.CollectionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.inject.Guice;
import com.google.inject.Injector;

public class PgpEncryption {

    private static final Logger PLAIN_LOGGER = LogManager.getLogger("plain_logger");
    private static final Logger LOGGER = LogManager.getLogger(PgpEncryption.class);

    private Processor processor;

    public static void main(String... args) {
        Injector injector = Guice.createInjector(new AppModule());

        PgpEncryption pgpEncryption = injector.getInstance(PgpEncryption.class);
        pgpEncryption.process(Arrays.asList(args));
    }

    @Inject
    public PgpEncryption(Processor processor) {
        this.processor = processor;
    }

    void process(List<String> arguments) {
        if (CollectionUtils.isEmpty(arguments) || arguments.size() < 2) {
            printUsage();
            return;
        }

        int createIndex = arguments.indexOf("-c");
        int encryptIndex = arguments.indexOf("-e");
        int decryptIndex = arguments.indexOf("-d");
        int fileIndex = arguments.indexOf("-f");
        int keyStoreIndex = arguments.indexOf("-k");

        try {
            if (createIndex >= 0) {
                String outputPath = arguments.get(createIndex + 1);
                processor.createKeys(outputPath);

            } else if (keyStoreIndex >= 0 && encryptIndex >= 0 && fileIndex >= 0 && arguments.size() >= 6) {
                String keyStore = arguments.get(keyStoreIndex + 1);
                String alias = arguments.get(encryptIndex + 1);
                String file = arguments.get(fileIndex + 1);
                char[] password = readPassword();
                processor.encryptFile(alias, file, keyStore, password);

            } else if (keyStoreIndex >= 0 && decryptIndex >= 0 && fileIndex >= 0 && arguments.size() >= 6) {
                String keyStore = arguments.get(keyStoreIndex + 1);
                String alias = arguments.get(decryptIndex + 1);
                String file = arguments.get(fileIndex + 1);
                char[] password = readPassword();
                processor.decryptFile(alias, file, keyStore, password);

            } else if (encryptIndex >= 0 && fileIndex >= 0 && arguments.size() >= 4) {
                String key = arguments.get(encryptIndex + 1);
                String file = arguments.get(fileIndex + 1);
                processor.encryptFile(key, file);

            } else if (decryptIndex >= 0 && fileIndex >= 0 && arguments.size() >= 4) {
                String key = arguments.get(decryptIndex + 1);
                String file = arguments.get(fileIndex + 1);
                processor.decryptFile(key, file);

            } else {
                LOGGER.error("Unrecognized parameters.");
                printUsage();
            }

        } catch (Exception e) {
            LOGGER.error("An error was thrown during process.", e);
        }
    }

    char[] readPassword() throws IOException {
        Console console = System.console();
        if (console == null) {
            String message = "Cannot ask for password. Are you running program from console?";
            LOGGER.error(message);
            throw new IllegalStateException(message);
        }
        return console.readPassword("Key Store password: ");
    }

    void printUsage() {
        PLAIN_LOGGER.error("Usage:");
        PLAIN_LOGGER.error("  -c [output folder]: Create keys and put them into this output folder.");
        PLAIN_LOGGER.error("  -e [key]: Encrypt file with public key. If -k is given -e names the alias of the key store. Used in combination with -f.");
        PLAIN_LOGGER.error("  -d [key]: Decrypt file with private key. If -k is given -d names the alias of the key store. Used in combination with -f.");
        PLAIN_LOGGER.error("  -f [input file]: File to encrypt or decrypt.");
        PLAIN_LOGGER.error("  -k [key store]: Key Store that holds private and public keys.");
    }

}
