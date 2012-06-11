package es.uji.apps.cryptoapplet.config.i18n;

import java.util.Enumeration;
import java.util.Properties;
import java.util.ResourceBundle;

public class LabelManager
{
    private static LabelManager i18n;
    private Properties _prop = new Properties();
    private static String _lang = null;

    public static void setLang(String lang)
    {
        _lang = lang;
        i18n = new LabelManager();
    }

    private LabelManager()
    {
        try
        {
            ResourceBundle bundle;

            if (_lang != null)
            {
                bundle = CustomBundleLoader.getBundle("i18n" + "_" + _lang);
            }
            else
            {
                bundle = CustomBundleLoader.getBundle("i18n");
            }

            Enumeration<String> enume = bundle.getKeys();
            String key = null;

            while (enume.hasMoreElements())
            {
                key = (String) enume.nextElement();
                _prop.put(key, bundle.getObject(key));
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    public static String get(String propName)
    {
        String translated;

        if (i18n == null)
        {
            i18n = new LabelManager();
        }

        try
        {
            translated = i18n._prop.getProperty(propName);
        }
        catch (Exception e)
        {
            // Untranslated message
            translated = "ERROR: UNTRANSLATED MESSAGE: " + propName;
        }

        return translated;
    }
}
