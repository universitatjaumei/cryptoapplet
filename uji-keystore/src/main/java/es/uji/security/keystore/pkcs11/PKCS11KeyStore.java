package es.uji.security.keystore.pkcs11;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import es.uji.security.crypto.config.StreamUtils;
import es.uji.security.keystore.BaseKeyStore;
import es.uji.security.keystore.SimpleKeyStore;

public class PKCS11KeyStore extends BaseKeyStore implements SimpleKeyStore
{
    @Override
    @SuppressWarnings("restriction")
    public void load(InputStream input, String password) throws GeneralSecurityException,
            IOException
    {
        super.load(input, password);
        
        byte[] config = StreamUtils.inputStreamToByteArray(input);
        this.provider = new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(config));

        keyStore = KeyStore.getInstance("PKCS11", provider);
        keyStore.load(input, password.toCharArray());
    }
}