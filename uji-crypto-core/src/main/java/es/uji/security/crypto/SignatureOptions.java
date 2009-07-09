package es.uji.security.crypto;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;

public class SignatureOptions
{

	private boolean _isByteArray = false;
	private boolean _isHash = false;
    private boolean _isLocalFile = false;
    private boolean swapToFile= false;
    private X509Certificate certificate = null;
    private PrivateKey privateKey = null;
    private Provider provider = null;
    byte[] toSign = null;
    InputStream toSign_is = null;

    public SignatureOptions()
    {

    }
    
    public boolean is_hash()
    {
        return _isHash;
    }

    public void set_ishash(boolean isHash)
    {
        _isHash = isHash;
    }

    public boolean is_localFile()
    {
        return _isLocalFile;
    }

    public void set_localFile(boolean isLocalfile)
    {
        _isLocalFile = isLocalfile;
    }

    public X509Certificate getCertificate()
    {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate)
    {
        this.certificate = certificate;
    }

    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey)
    {
        this.privateKey = privateKey;
    }

    public Provider getProvider()
    {
        return provider;
    }

    public void setProvider(Provider provider)
    {
        this.provider = provider;
    }

    public InputStream getToSignInputStream()
    {
        return this.toSign_is;
    }

    public void setToSignInputstream(InputStream is)
    {
        this.toSign_is = is;
    }
    
    public void setSwapToFile(boolean value){
    	this.swapToFile= value;
    }
   
    public boolean getSwapToFile(){
    	return this.swapToFile;
    }
}
