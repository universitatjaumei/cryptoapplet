package es.uji.security.keystore.mscapi;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import es.uji.security.keystore.BaseKeyStore;
import es.uji.security.keystore.SimpleKeyStore;

public class SunMSCAPIKeyStore extends BaseKeyStore implements SimpleKeyStore
{
    @Override
    public void load(InputStream input, String password) throws GeneralSecurityException,
            IOException
    {
        super.load(input, password);

        keyStore = KeyStore.getInstance("Windows-MY", provider);
        keyStore.load(input, password.toCharArray());
    }
}