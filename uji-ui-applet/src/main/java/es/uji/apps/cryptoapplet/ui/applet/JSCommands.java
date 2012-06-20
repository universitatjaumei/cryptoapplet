package es.uji.apps.cryptoapplet.ui.applet;

import javax.swing.JApplet;

import netscape.javascript.JSObject;

import org.apache.log4j.Logger;

import es.uji.apps.cryptoapplet.crypto.Browser;

public class JSCommands
{
    private Logger log = Logger.getLogger(JSCommands.class);

    private static JSObject browserWindow = null;
    private static JSCommands singleton = null;

    private JSCommands(JApplet owner)
    {
        log.debug("New access to browser window from Applet");

        browserWindow = JSObject.getWindow(owner);
    }

    public static JSCommands getInstance(JApplet owner)
    {
        if (singleton == null)
        {
            singleton = new JSCommands(owner);
        }

        return singleton;
    }

    public JSObject getWindow()
    {
        return browserWindow;
    }

    private void callJavaScriptFunction(String functionName, String[] params)
    {
        log.debug("Call JavaScript " + functionName);
        getWindow().call(functionName, params);
    }

    public void onInitOk()
    {
        callJavaScriptFunction("onInitOk", new String[] {});
    }

    public void onSignError()
    {
        callJavaScriptFunction("onSignError", new String[] {});
    }

    public void onSignCancel()
    {
        callJavaScriptFunction("onSignCancel", new String[] {});
    }

    public void onWindowShow()
    {
        callJavaScriptFunction("onWindowShow", new String[] {});
    }

    public Browser getSupportedBrowser()
    {
        JSObject document = (JSObject) getWindow().getMember("navigator");
        String userAgent = (String) document.getMember("userAgent");

        if (userAgent != null)
        {
            userAgent = userAgent.toLowerCase();

            log.debug("Detected user agent " + userAgent);

            if (userAgent.contains("explorer") || userAgent.contains("msie"))
            {
                return Browser.IEXPLORER;
            }
        }

        return Browser.FIREFOX;
    }
}