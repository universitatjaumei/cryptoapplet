package es.uji.security.crypto;

import es.uji.security.crypto.config.OS;

public enum SupportedBrowser
{
    IEXPLORER,
    MOZILLA,
    OTHERS,
    CHROME,
    SAFARI,
    OPERA;

    public static boolean isIE(String userAgent)
    {
        return userAgent.indexOf("trident/") > -1 ||
                userAgent.indexOf("explorer") > -1 ||
                userAgent.indexOf("msie") > -1;
    }

    public static boolean isChromeWindows(String userAgent)
    {
        return OS.isWindowsUpperEqualToNT() && isChrome(userAgent);
    }

    public static boolean isMozilla(String userAgent)
    {
        return userAgent.indexOf("firefox") > -1 ||
                userAgent.indexOf("iceweasel") > -1 ||
                userAgent.indexOf("seamonkey") > -1 ||
                userAgent.indexOf("gecko") > -1 ||
                userAgent.indexOf("netscape") > -1;
    }

    public static boolean isChrome(String userAgent)
    {
        return userAgent.indexOf("chrome/") > -1;
    }
}
