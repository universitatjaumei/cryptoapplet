package es.uji.security.ui.applet;

import javax.swing.JApplet;

import org.apache.log4j.Logger;

import netscape.javascript.JSObject;

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
}