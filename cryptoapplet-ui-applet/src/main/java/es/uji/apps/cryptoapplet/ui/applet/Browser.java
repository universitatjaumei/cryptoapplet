package es.uji.apps.cryptoapplet.ui.applet;

import javax.swing.JApplet;

import netscape.javascript.JSObject;

import org.apache.log4j.Logger;

import es.uji.apps.cryptoapplet.crypto.BrowserType;

public class Browser
{
    private static Logger log = Logger.getLogger(Browser.class);

    private static JSObject browserWindow;

    private Browser()
    {
    }

    public static Browser getInstance(JApplet applet)
    {
        if (browserWindow == null)
        {
            log.debug("Detected new access to browser window from applet");
            browserWindow = JSObject.getWindow(applet);
        }

        return new Browser();
    }

    public void clearInstance()
    {
        browserWindow = null;
    }

    public JSObject getWindow()
    {
        return browserWindow;
    }

    public JSObject getNavigator()
    {
        return (JSObject) getWindow().getMember("navigator");
    }

    public String getUserAgent()
    {
        String userAgent = (String) getNavigator().getMember("userAgent");

        log.debug("Detected browser userAgent " + userAgent);

        return userAgent;
    }

    private void commandExecution(String commandName)
    {
        log.debug("Call JavaScript method \"" + commandName + "\"");

        browserWindow.call(commandName, new String[] {});
    }

    public void initOk()
    {
        commandExecution("onInitOk");
    }

    public void signOk()
    {
        commandExecution("onSignOk");
    }

    public void signError()
    {
        commandExecution("onSignError");
    }

    public void signCancel()
    {
        commandExecution("onSignCancel");
    }

    public void windowShow()
    {
        commandExecution("onWindowShow");
    }

    public BrowserType getDetectedBrowser()
    {
        String userAgent = getUserAgent();
        BrowserType navigator = BrowserType.FIREFOX;

        if (userAgent != null)
        {
            userAgent = userAgent.toLowerCase();

            if (userAgent.contains("chrome/"))
            {
                navigator = BrowserType.CHROME;
            }
            else if (userAgent.contains("safari/"))
            {
                navigator = BrowserType.SAFARI;
            }
            else if (userAgent.contains("opera ") || userAgent.contains("opera/"))
            {
                navigator = BrowserType.OPERA;
            }
            else if (userAgent.contains("msie "))
            {
                navigator = BrowserType.IEXPLORER;
            }

            log.debug("Navigator variable set to " + navigator);
        }

        return navigator;
    }

    public boolean isInternetExplorer()
    {
        return BrowserType.IEXPLORER.equals(getUserAgent());
    }

    public boolean isMozillaFirefox()
    {
        return BrowserType.FIREFOX.equals(getUserAgent());
    }

    public boolean isChrome()
    {
        return BrowserType.CHROME.equals(getUserAgent());
    }

    public boolean isSafari()
    {
        return BrowserType.SAFARI.equals(getUserAgent());
    }

    public boolean isOpera()
    {
        return BrowserType.OPERA.equals(getUserAgent());
    }
}