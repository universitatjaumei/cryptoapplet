package es.uji.apps.cryptoapplet.config.i18n;

import java.io.IOException;
import java.util.Locale;
import java.util.Properties;

public class LabelManager
{
    private Properties properties;

    public LabelManager(Locale locale) throws TranslationFileNotFoundException,
            TranslationFileLoadException
    {
        TranslationsLoader customBundleLoader = new TranslationsLoader();
        properties = new Properties();

        try
        {
            properties.load(customBundleLoader.getBundle(locale));
        }
        catch (IOException e)
        {
            throw new TranslationFileLoadException();
        }
    }

    public String get(String propertyName)
    {
        if (properties.containsKey(propertyName))
        {
            return properties.getProperty(propertyName);
        }

        return "<untranslated>" + propertyName;
    }
}