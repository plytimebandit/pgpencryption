package org.plytimebandit.tools.pgpencryption;

import com.google.inject.Guice;
import com.google.inject.Injector;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import picocli.CommandLine;

import javax.inject.Inject;
import java.io.Console;
import java.util.concurrent.Callable;

@CommandLine.Command(
        name = "PGP Encryption",
        description = "PGP Encryption can be used to encrypt and decrypt files.")
public class PgpEncryption implements Callable<Integer> {

    private static final Logger PLAIN_LOGGER = LogManager.getLogger("plain_logger");
    private static final Logger LOGGER = LogManager.getLogger(PgpEncryption.class);

    private final Processor processor;

    @CommandLine.Option(names = "-h", paramLabel = "help", usageHelp = true, description = "Show help.")
    boolean usageHelpRequested;

    @CommandLine.Option(names = "-c", paramLabel = "create key pair", description = "Create keys and put them into this output folder.")
    String createKeysToTargetDir;

    @CommandLine.Option(names = "-e", paramLabel = "encryption key", description = "Encrypt file with public key. If -k is given -e names the alias of the key store. Used in combination with -f.")
    String publicKeyOrKeyStoreAlias;

    @CommandLine.Option(names = "-d", paramLabel = "decryption key", description = "Decrypt file with private key. If -k is given -d names the alias of the key store. Used in combination with -f.")
    String privateKeyOrKeyStoreAlias;

    @CommandLine.Option(names = "-f", paramLabel = "file", description = "File to encrypt or decrypt.")
    String fileNameToProcess;

    @CommandLine.Option(names = "-k", paramLabel = "key store", description = "Key Store that holds private and public keys.")
    String keyStore;

    private CommandLine commandLine;

    public static void main(String... args) {
        Injector injector = Guice.createInjector(new AppModule());

        PgpEncryption pgpEncryption = injector.getInstance(PgpEncryption.class);

        int exitCode = pgpEncryption.parseArgsAndExecute(args);
        System.exit(exitCode);
    }

    @Inject
    public PgpEncryption(Processor processor) {
        this.processor = processor;
    }

    int parseArgsAndExecute(String... args) {
        commandLine = new CommandLine(this);
        commandLine.parseArgs(args);
        if (usageHelpRequested) {
            printUsage();
            return 0;
        }
        return commandLine.execute(args);
    }

    @Override
    public Integer call() {
        process();
        return 0;
    }

    private void process() {
        if (StringUtils.isAllBlank(createKeysToTargetDir, publicKeyOrKeyStoreAlias, privateKeyOrKeyStoreAlias,
                fileNameToProcess, keyStore)) {
            printUsage();
            return;
        }

        try {
            if (StringUtils.isNotBlank(createKeysToTargetDir)) {
                processor.createKeys(createKeysToTargetDir);

            } else if (StringUtils.isNoneBlank(keyStore, publicKeyOrKeyStoreAlias, fileNameToProcess)) {
                char[] password = readPassword();
                processor.encryptFile(publicKeyOrKeyStoreAlias, fileNameToProcess, keyStore, password);

            } else if (StringUtils.isNoneBlank(keyStore, privateKeyOrKeyStoreAlias, fileNameToProcess)) {
                char[] password = readPassword();
                processor.decryptFile(privateKeyOrKeyStoreAlias, fileNameToProcess, keyStore, password);

            } else if (StringUtils.isNoneBlank(publicKeyOrKeyStoreAlias, fileNameToProcess)) {
                processor.encryptFile(publicKeyOrKeyStoreAlias, fileNameToProcess);

            } else if (StringUtils.isNoneBlank(privateKeyOrKeyStoreAlias, fileNameToProcess)) {
                processor.decryptFile(privateKeyOrKeyStoreAlias, fileNameToProcess);

            } else {
                LOGGER.error("Unrecognized parameters.");
                printUsage();
            }

        } catch (Exception e) {
            LOGGER.error("An error was thrown during process.", e);
        }
    }

    char[] readPassword() {
        Console console = System.console();
        if (console == null) {
            String message = "Cannot ask for password. Are you running program from console?";
            LOGGER.error(message);
            throw new IllegalStateException(message);
        }
        return console.readPassword("Key Store password: ");
    }

    void printUsage() {
        PLAIN_LOGGER.warn(commandLine.getUsageMessage());
    }

}
