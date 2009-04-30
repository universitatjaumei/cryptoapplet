package es.uji.security.util.net;

import java.io.DataInputStream;
import java.io.IOException;

public class SocketDataInputStreamReader
{
    private DataInputStream _dis;

    public SocketDataInputStreamReader(DataInputStream dis)
    {
        _dis = dis;
    }

    public byte readByte() throws IOException
    {
        return _dis.readByte();
    }

    public int readInt() throws IOException
    {
        return Integer.reverseBytes(_dis.readInt());
    }

    public byte[] readByteArray(int size) throws IOException
    {
        int read = 0, err = 0;
        byte[] res = new byte[size];

        while (read < size)
        {
            err = _dis.read(res, read, size - read);
            if (err == -1)
            {
                throw new IOException("ErrorReadingFromSocket");
            }
            else
            {
                read += err;
            }
        }
        return res;
    }
}
