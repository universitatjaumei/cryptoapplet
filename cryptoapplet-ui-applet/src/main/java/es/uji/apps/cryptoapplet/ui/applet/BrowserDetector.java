package es.uji.apps.cryptoapplet.ui.applet;

import org.apache.log4j.Logger;

import es.uji.apps.cryptoapplet.crypto.Browser;

public class BrowserDetector
{
    private static Logger log = Logger.getLogger(BrowserDetector.class);

    private static Browser navigator;

    private static Browser getDetectedBrowser()
    {
        if (navigator == null)
        {
            String userAgent = BrowserWindowInfo.getUserAgent();

            if (userAgent != null)
            {
                userAgent = userAgent.toLowerCase();

                if (userAgent.contains("explorer") || userAgent.contains("msie"))
                {
                    navigator = Browser.IEXPLORER;

                }
                else
                {
                    navigator = Browser.FIREFOX;
                }
            }

            log.debug("Navigator variable set to " + navigator);
        }

        return navigator;
    }

    public static boolean isInternetExplorer()
    {
        return Browser.IEXPLORER.equals(getDetectedBrowser());
    }

    public static boolean isMozillaFirefox()
    {
        return Browser.FIREFOX.equals(getDetectedBrowser());
    }
}