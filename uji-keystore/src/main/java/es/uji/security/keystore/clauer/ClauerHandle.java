package es.uji.security.keystore.clauer;

import java.net.Socket;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class ClauerHandle
{
    public String path;
    public Socket s;
    public DataOutputStream outStream = null;
    public DataInputStream inStream = null;
    byte[] idDisp = new byte[20];

    public void initInputOutput() throws IOException
    {
        outStream = new DataOutputStream(s.getOutputStream());
        inStream = new DataInputStream(s.getInputStream());
    }

    public void cleanUp() throws IOException
    {
        // s.shutdownInput();
        // s.shutdownOutput();
        s.close();
        outStream.close();
        inStream.close();

        s = null;
        outStream = null;
        inStream = null;
    }

    public void setId(byte[] id)
    {
        for (int i = 0; i < 20; i++)
        {
            idDisp[i] = id[i];
        }
    }
}