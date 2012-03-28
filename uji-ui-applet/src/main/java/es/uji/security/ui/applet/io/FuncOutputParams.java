package es.uji.security.ui.applet.io;

import java.io.IOException;
import java.io.InputStream;
import java.util.Hashtable;

import es.uji.security.crypto.config.StreamUtils;
import es.uji.security.ui.applet.SignatureApplet;

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

    public void setSignData(InputStream is) throws IOException
    {

        byte[] data = StreamUtils.inputStreamToByteArray(is);

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
