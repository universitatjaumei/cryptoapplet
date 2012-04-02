package es.uji.security.keystore.pkcs11;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

import es.uji.security.crypto.config.StreamUtils;
import es.uji.security.keystore.BaseKeyStore;
import es.uji.security.keystore.SimpleKeyStore;

public class PKCS11KeyStore extends BaseKeyStore implements SimpleKeyStore
{
    @Override
    public void load(InputStream input, String password) throws GeneralSecurityException,
            IOException
    {
        super.load(input, password);

        provider = getProvider(input);
        keyStore = KeyStore.getInstance("PKCS11", provider);

        char[] keyStorePassword = (password != null) ? password.toCharArray() : null;
        keyStore.load(input, keyStorePassword);
    }

    @SuppressWarnings("restriction")
    private Provider getProvider(InputStream input) throws IOException
    {
        if (!providerAlreadyLoaded())
        {
            byte[] config = StreamUtils.inputStreamToByteArray(input);
            Provider provider = new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(config));
            Security.addProvider(provider);

            return provider;
        }

        return Security.getProvider("SunPKCS11-DNIe");
    }

    private boolean providerAlreadyLoaded()
    {
        for (Provider provider : Security.getProviders())
        {
            if (provider.getName().startsWith("SunPKCS11-DNIe"))
            {
                return true;
            }
        }

        return false;
    }
}