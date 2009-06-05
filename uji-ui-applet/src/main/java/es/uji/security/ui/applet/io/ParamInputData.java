package es.uji.security.ui.applet.io;

import java.util.Hashtable;

import es.uji.security.ui.applet.SignatureApplet;

public class ParamInputData extends AbstractData implements InputParams
{

    private String[] str_in;
    private int _current = 0;
    private int _count = 0;

    public ParamInputData(String[] in)
    {
        this.str_in = in;
        _count = this.str_in.length;
    }

    public int getInputCount() throws Exception
    {
        return _count;
    }

    public byte[] getSignData() throws Exception
    {

        byte[] ret = this.str_in[_current].getBytes();

        if (mustHash)
            ret = AbstractData.getMessageDigest(ret);

        _current++;

        return ret;
    }

    public byte[] getSignData(int item) throws Exception
    {
        // TODO Auto-generated method stub
        return null;
    }

    public String getSignFormat(SignatureApplet base)
    {
        // TODO Auto-generated method stub
        return null;
    }

    public void initialize(Hashtable<String, Object> props)
    {
        // TODO Auto-generated method stub

    }

    public void flush()
    {
        // TODO Auto-generated method stub

    }

}
