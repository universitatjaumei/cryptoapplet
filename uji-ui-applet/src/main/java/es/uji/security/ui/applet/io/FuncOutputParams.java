package es.uji.security.ui.applet.io;

import java.io.IOException;
import java.io.InputStream;
import java.util.Hashtable;

import es.uji.security.crypto.config.OS;
import es.uji.security.ui.applet.SignatureApplet;

public class FuncOutputParams implements OutputParams
{
    private String fun, onSignOk = "onSignOk";
    private byte[] bstrSig = null;
    private String strSig = null;
    SignatureApplet sap;

    public FuncOutputParams(SignatureApplet sap, String onSignOk)
    {
        this.onSignOk = onSignOk;
        this.sap = sap;
    }

    public void setSignData(InputStream is, int currentIndex) throws IOException
    {

    	byte[] data= OS.inputStreamToByteArray(is);
    	
        strSig = new String(data);
        commit();
    }

    public void setSignFormat(Hashtable<String, Object> params, byte[] signFormat)
            throws IOException
    {
    }

    public void setSignFormat(byte[] signFormat) throws IOException
    {
    }

    private void commit()
    {
        if (strSig != "")
            netscape.javascript.JSObject.getWindow(sap)
                    .call(this.onSignOk, new String[] { strSig });
    }

    public void signOk()
    {
        if (strSig != "")
            netscape.javascript.JSObject.getWindow(sap)
                    .call(this.onSignOk, new String[] { strSig });
    }

    public void flush()
    {
    }
}
