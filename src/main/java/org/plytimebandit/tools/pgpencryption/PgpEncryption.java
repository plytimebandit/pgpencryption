package org.plytimebandit.tools.pgpencryption;

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
//        int keyStoreIndex = arguments.indexOf("-k");
//        int keyStoreAliasIndex = arguments.indexOf("-a");

        try {
            if (createIndex >= 0) {
                String outputPath = arguments.get(createIndex + 1);
                processor.createKeys(outputPath);

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

    void printUsage() {
        PLAIN_LOGGER.error("Usage:");
        PLAIN_LOGGER.error("  -c [output folder]: Create keys into output folder.");
        PLAIN_LOGGER.error("  -e [key]: Encrypt file with key. Used in combination with -f.");
        PLAIN_LOGGER.error("  -d [key]: Decrypt file with key. Used in combination with -f.");
        PLAIN_LOGGER.error("  -f [input file]: Given file to encrypt or decrypt.");
    }

}
