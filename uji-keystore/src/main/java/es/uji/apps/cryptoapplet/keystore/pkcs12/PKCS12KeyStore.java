package es.uji.apps.cryptoapplet.keystore.pkcs12;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.uji.apps.cryptoapplet.keystore.BaseKeyStore;
import es.uji.apps.cryptoapplet.keystore.SimpleKeyStore;

public class PKCS12KeyStore extends BaseKeyStore implements SimpleKeyStore
{
    public void load(InputStream input, String password) throws GeneralSecurityException,
            IOException
    {
        super.load(input, password);

        keyStore = KeyStore.getInstance("PKCS12", new BouncyCastleProvider());
        keyStore.load(input, password.toCharArray());
    }
}