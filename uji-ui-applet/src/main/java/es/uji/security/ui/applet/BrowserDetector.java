package es.uji.security.ui.applet;

import org.apache.log4j.Logger;

import es.uji.security.crypto.SupportedBrowser;

public class BrowserDetector
{
    private static Logger log = Logger.getLogger(BrowserDetector.class);

    private static SupportedBrowser navigator;

    private static SupportedBrowser getDetectedBrowser()
    {
        if (navigator == null)
        {
            String userAgent = BrowserWindowInfo.getUserAgent();

            if (userAgent != null)
            {
                userAgent = userAgent.toLowerCase();

                if (userAgent.contains("explorer") || userAgent.contains("msie"))
                {
                    navigator = SupportedBrowser.IEXPLORER;

                }
                else
                {
                    navigator = SupportedBrowser.FIREFOX;
                }
            }

            log.debug("Navigator variable set to " + navigator);
        }

        return navigator;
    }

    public static boolean isInternetExplorer()
    {
        return SupportedBrowser.IEXPLORER.equals(getDetectedBrowser());
    }

    public static boolean isMozillaFirefox()
    {
        return SupportedBrowser.FIREFOX.equals(getDetectedBrowser());
    }
}