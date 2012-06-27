package es.uji.apps.cryptoapplet.config;

import static org.junit.Assert.assertEquals;

import java.util.Locale;

import org.junit.Test;

import es.uji.apps.cryptoapplet.config.i18n.LabelManager;
import es.uji.apps.cryptoapplet.config.i18n.TranslationFileNotFoundException;

public class LabelManagerTest
{
    @Test
    public void existingLanguageBundlesShouldBeLoadedByLabelManager() throws Exception
    {
        LabelManager labelManager = new LabelManager(new Locale("ca_CA"));
        assertEquals("Signatura digital", labelManager.get("WINDOW_TITLE"));
    }

    @Test(expected = TranslationFileNotFoundException.class)
    public void nonExistingTranslationFilesShouldThrowsException() throws Exception
    {
        new LabelManager(new Locale("es_MX"));
    }
}
