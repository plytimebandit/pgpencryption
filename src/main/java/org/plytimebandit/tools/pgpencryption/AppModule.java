package org.plytimebandit.tools.pgpencryption;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.inject.AbstractModule;

public class AppModule extends AbstractModule {

    AppModule() {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        if (Security.getProvider(provider.getName()) == null) {
            Security.addProvider(provider);
        }
    }

    @Override
    protected void configure() {

    }
}
