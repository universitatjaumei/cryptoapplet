package es.uji.dsign.applet2.junit;

import java.util.Hashtable;
import javax.swing.JApplet;

import es.uji.security.ui.applet.SignatureApplet;

public class TestApplet extends SignatureApplet
{

    private Hashtable<String, String> htparams = new Hashtable<String, String>();

    public TestApplet()
    {

    }

    public void setParameters(String[][] params)
    {
        for (int i = 0; i < params.length; i++)
        {
            htparams.put(params[i][0], params[i][1]);
        }
    }

    public String getParameter(String param)
    {
        return htparams.get(param);
    }

    public void deleteParams()
    {
        htparams.clear();
    }
}
