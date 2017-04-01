package org.plytimebandit.tools.pgpencryption;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.inject.AbstractModule;
import com.google.inject.name.Names;

public class AppModule extends AbstractModule {

    AppModule() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    protected void configure() {
        bindConstant().annotatedWith(Names.named("keySize")).to(4096);
        bindConstant().annotatedWith(Names.named("algorithm")).to("RSA");
    }
}
