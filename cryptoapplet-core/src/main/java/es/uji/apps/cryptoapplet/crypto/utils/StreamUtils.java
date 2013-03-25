package es.uji.apps.cryptoapplet.crypto.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class StreamUtils
{
    public static byte[] inputStreamToByteArray(InputStream in)
    {
        byte[] buffer = new byte[2048];
        int length = 0;

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try
        {
            while ((length = in.read(buffer)) >= 0)
            {
                baos.write(buffer, 0, length);
            }

            return baos.toByteArray();
        }
        catch (IOException e)
        {
            return null;
        }
    }
}