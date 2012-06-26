package es.uji.apps.cryptoapplet.config.i18n;

import java.io.InputStream;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class TranslationsLoader
{
    private Map<String, InputStream> bundles;

    public TranslationsLoader()
    {
        bundles = new HashMap<String, InputStream>();
    }

    public InputStream getBundle(Locale locale) throws TranslationFileNotFoundException
    {
        String bundleKey = locale.getLanguage();

        if (bundles.get(bundleKey) == null)
        {
            InputStream resource = loadBundle(bundleKey);

            if (resource != null)
            {
                bundles.put(locale.getLanguage(), resource);
            }
            else
            {
                throw new TranslationFileNotFoundException();
            }
        }

        return bundles.get(bundleKey);
    }

    private InputStream loadBundle(String bundleName)
    {
        return ClassLoader.getSystemResourceAsStream(MessageFormat.format("i18n/{0}.properties",
                bundleName));
    }
}