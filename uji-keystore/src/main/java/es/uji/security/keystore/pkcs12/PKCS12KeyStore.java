package es.uji.security.keystore.pkcs12;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import es.uji.security.keystore.BaseKeyStore;
import es.uji.security.keystore.SimpleKeyStore;

public class PKCS12KeyStore extends BaseKeyStore implements SimpleKeyStore
{
    public void load(InputStream input, String password) throws GeneralSecurityException,
            IOException
    {
        super.load(input, password);

        keyStore = KeyStore.getInstance("PKCS12", provider);
        keyStore.load(input, password.toCharArray());
    }
}