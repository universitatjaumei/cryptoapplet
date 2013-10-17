package es.uji.apps.cryptoapplet.ui.service.model;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

public class RemoteContentManager
{
    public InputStream getData(String inputUrl) throws IOException
    {
        URL url = new URL(inputUrl);
        URLConnection uc = url.openConnection();

        uc.setConnectTimeout(10000);
        uc.setReadTimeout(10000);

        uc.connect();

        return uc.getInputStream();
    }
}
