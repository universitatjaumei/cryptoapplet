package es.uji.apps.cryptoapplet.config.i18n;

import java.io.InputStream;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.apache.log4j.Logger;

public class TranslationsLoader
{
    private Logger log = Logger.getLogger(TranslationsLoader.class);

    private Map<String, InputStream> bundles;

    public TranslationsLoader()
    {
        bundles = new HashMap<String, InputStream>();
    }

    public InputStream getBundle(Locale locale) throws TranslationFileNotFoundException
    {
        String bundleKey = locale.toString().toLowerCase();

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
        log.info(MessageFormat.format("Loading i18n/{0}.properties", bundleName));

        return ClassLoader.getSystemClassLoader().getResourceAsStream(
                MessageFormat.format("i18n/{0}.properties", bundleName));
    }
}