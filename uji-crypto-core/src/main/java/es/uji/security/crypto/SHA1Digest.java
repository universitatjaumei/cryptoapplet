package es.uji.security.crypto;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * Message digest security provider interface for our security provider.
 * 
 * @author PSN
 */

public class SHA1Digest extends MessageDigestSpi
{
    private ByteArrayOutputStream _buffer;
    private MessageDigest _md;

    public SHA1Digest() throws NoSuchAlgorithmException
    {
        super();
        _md = MessageDigest.getInstance("SHA1");
        engineReset();
    }

    public SHA1Digest(Provider provider, String algorithm) throws NoSuchAlgorithmException
    {
        super();
        _md = MessageDigest.getInstance("SHA1", provider);
        engineReset();
    }

    public void engineReset()
    {
        _buffer = new ByteArrayOutputStream();
    }

    public void engineUpdate(byte b)
    {
        _buffer.write(b);
    }

    public void engineUpdate(byte[] b, int ofs, int len)
    {
        _buffer.write(b, ofs, len);
    }

    public byte[] engineDigest()
    {
        byte[] data = _buffer.toByteArray();

        _md.update(data);

        byte[] digest = _md.digest();

        engineReset();
        _md.reset();

        return digest;
    }
}