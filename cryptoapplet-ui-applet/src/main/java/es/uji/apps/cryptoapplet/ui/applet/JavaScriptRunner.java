package es.uji.apps.cryptoapplet.ui.applet;

import org.apache.log4j.Logger;

public class JavaScriptRunner
{
    private static Logger log = Logger.getLogger(SignatureApplet.class);
    
    private static void commandExecution(String commandName)
    {
        log.debug("Call JavaScript method \"" + commandName + "\"");

        BrowserWindowInfo.getWindow().call(commandName, new String[] {});        
    }

    public static void initOk()
    {
        commandExecution("onInitOk");
    }

    public static void signOk()
    {
        commandExecution("onSignOk");
    }

    public static void signError()
    {
        commandExecution("onSignError");
    }

    public static void signCancel()
    {
        commandExecution("onSignCancel");
    }

    public static void windowShow()
    {
        commandExecution("onWindowShow");
    }
}