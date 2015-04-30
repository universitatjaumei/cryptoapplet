package es.uji.security.ui.applet.io;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
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

    public InputStream getSignData() throws Exception
    {
    	
    	byte[] ret = this.str_in[_current].getBytes();

        if (mustHash)
            ret = AbstractData.getMessageDigest(ret);
 
        _current++;

        return new ByteArrayInputStream(ret);
    }

    public InputStream getSignData(int item) throws Exception
    {
        byte[] ret = this.str_in[item].getBytes();

        if (mustHash)
            ret = AbstractData.getMessageDigest(ret);
 
        return new ByteArrayInputStream(ret);
    }

    public String getSignFormat(SignatureApplet base)
    {
        return base.getParameter("signFormat");
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
