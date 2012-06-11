package es.uji.apps.cryptoapplet.config.i18n;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.PropertyResourceBundle;
import java.util.ResourceBundle;

public class CustomBundleLoader
{
    private static final Map<String, ResourceBundle> BUNDLES = new HashMap<String, ResourceBundle>();

    public static ResourceBundle getBundle(String name)
    {
        synchronized (BUNDLES)
        {
            ResourceBundle bundle = BUNDLES.get(name);
            if (bundle == null)
            {
                ClassLoader loader = getContextClassLoader();
                bundle = loadBundle(loader, name.replace('.', '/') + ".properties");
                BUNDLES.put(name, bundle);
            }
            return bundle;
        }
    }

    private static ClassLoader getContextClassLoader()
    {
        return Thread.currentThread().getContextClassLoader() != null ? Thread.currentThread()
                .getContextClassLoader()
                : CustomBundleLoader.class.getClassLoader() != null ? CustomBundleLoader.class
                        .getClassLoader() : ClassLoader.getSystemClassLoader();
    }

    private static ResourceBundle loadBundle(ClassLoader loader, String res)
    {
        try
        {
            InputStream in = loader.getResourceAsStream(res);
            try
            {
                return new PropertyResourceBundle(in);
            }
            finally
            {
                in.close();
            }
        }
        catch (IOException e)
        {
            throw new IllegalStateException(e.toString());
        }
    }
}