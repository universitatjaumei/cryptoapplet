package es.uji.security.ui.applet.io;

import java.io.IOException;
import java.util.Hashtable;

import es.uji.security.ui.applet.SignatureApplet;
import es.uji.security.util.Base64;

public class FuncOutputParams implements OutputParams
{
    private String fun, onSignOk = "onSignOk";
    private byte[] bstrSig = null;
    private String strSig = null;
    private int _count = 1;
    private int _current = 0;
    SignatureApplet sap;

    public FuncOutputParams(SignatureApplet sap, String onSignOk)
    {
        this.onSignOk = onSignOk;
        this.sap = sap;
    }

    public void setSignData(byte[] data) throws IOException
    {

        strSig = new String(data);

        if (_count > 1 && (_current != (_count - 1)))
        {
            commit();
            _current++;
        }

    }

    public void setCount(int count)
    {
        this._count = count;
    }

    public void setSignFormat(Hashtable<String, Object> params, byte[] signFormat)
            throws IOException
    {
        // TODO Auto-generated method stub

    }

    public void setSignFormat(byte[] signFormat) throws IOException
    {
        // TODO Auto-generated method stub

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
        // TODO Auto-generated method stub

    }

}
