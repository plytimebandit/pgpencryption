package org.plytimebandit.tools.pgpencryption;

import java.util.Arrays;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.inject.Guice;
import com.google.inject.Injector;

public class PgpEncryption {

    private static final Logger PLAIN_LOGGER = LogManager.getLogger("plain_logger");

    public static void main(String... args) {
        if (args == null || args.length < 2) {
            printUsage();
            return;
        }

        Injector injector = Guice.createInjector(new AppModule());
        Processor processor = injector.getInstance(Processor.class);

        List<String> arguments = Arrays.asList(args);
        int createIndex = arguments.indexOf("-c");
        int encryptIndex = arguments.indexOf("-e");
        int decryptIndex = arguments.indexOf("-d");
        int fileIndex = arguments.indexOf("-f");

        try {
            if (createIndex >= 0) {
                String outputPath = arguments.get(createIndex + 1);
                processor.createKeys(outputPath);

            } else if (encryptIndex >= 0 && fileIndex >= 0 && args.length >= 4) {
                String key = arguments.get(encryptIndex + 1);
                String file = arguments.get(fileIndex + 1);
                processor.encryptFile(key, file);

            } else if (decryptIndex >= 0 && fileIndex >= 0 && args.length >= 4) {
                String key = arguments.get(decryptIndex + 1);
                String file = arguments.get(fileIndex + 1);
                processor.decryptFile(key, file);

            } else {
                PLAIN_LOGGER.error("Unrecognized parameters.");
                printUsage();
            }

        } catch (Exception e) {
            PLAIN_LOGGER.error("An error was thrown during process.");
            String message = e.getMessage();
            if (message != null && message.length() > 0) {
                PLAIN_LOGGER.error("  -> " + message);
            }
            printUsage();
        }
    }

    private static void printUsage() {
        PLAIN_LOGGER.error("Usage:");
        PLAIN_LOGGER.error("  -c [output folder]: Create keys into output folder.");
        PLAIN_LOGGER.error("  -e [key]: Encrypt file with key. Used in combination with -f.");
        PLAIN_LOGGER.error("  -d [key]: Decrypt file with key. Used in combination with -f.");
        PLAIN_LOGGER.error("  -f [input file]: Given file to encrypt or decrypt.");
    }

}
