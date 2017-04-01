package org.plytimebandit.tools.pgpencryption;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.inject.AbstractModule;

public class AppModule extends AbstractModule {

    AppModule() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    protected void configure() {

    }
}
