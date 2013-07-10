package es.uji.apps.cryptoapplet.ui.service.rest;

import es.uji.apps.cryptoapplet.keystore.KeyStoreManager;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.GeneralSecurityException;

public abstract class AbstractBaseResource
{
    protected KeyStoreManager keyStoreManager;

    public AbstractBaseResource() throws GeneralSecurityException, IOException
    {
        keyStoreManager = new KeyStoreManager();
    }

    protected InputStream getData(String inputUrl) throws IOException
    {
        URL url = new URL(inputUrl);
        URLConnection uc = url.openConnection();

        uc.setConnectTimeout(10000);
        uc.setReadTimeout(10000);

        uc.connect();

        return uc.getInputStream();
    }
}
