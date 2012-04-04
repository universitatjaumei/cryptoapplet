package es.uji.security.ui.applet;

import javax.swing.JApplet;

import netscape.javascript.JSObject;

import org.apache.log4j.Logger;

public class BrowserWindowInfo
{
    private static Logger log = Logger.getLogger(BrowserWindowInfo.class);

    private static JSObject browserWindow = null;

    private BrowserWindowInfo()
    {
    }

    public static JSObject getInstance(JApplet applet)
    {
        if (browserWindow == null)
        {
            log.debug("Detected new access to browser window from applet");
            
            browserWindow = JSObject.getWindow(applet);
        }

        return browserWindow;
    }

    public static void clearInstance()
    {
        browserWindow = null;
    }

    public static JSObject getWindow()
    {
        return browserWindow;
    }

    public static JSObject getNavigator()
    {
        return (JSObject) getWindow().getMember("navigator");
    }

    public static String getUserAgent()
    {
        String userAgent = (String) getNavigator().getMember("userAgent");
        
        log.debug("Detected browser userAgent " + userAgent);
        
        return userAgent;
    }
}