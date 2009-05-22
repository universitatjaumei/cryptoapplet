package sun.security.timestamp;

import java.io.IOException;

public class TSResponseFactory
{
    public static TSResponse getTSResponseInstance(byte[] data) throws IOException
    {
        return new TSResponse(data);
    }
}
