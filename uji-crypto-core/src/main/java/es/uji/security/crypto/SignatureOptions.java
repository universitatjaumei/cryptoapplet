package es.uji.security.crypto;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class SignatureOptions
{
    private X509Certificate certificate;
    private PrivateKey privateKey;
    private Provider provider;
    private InputStream dataToSign;

    private boolean hash = false;
    private boolean localFile = false;
    private boolean swapToFile = false;
    private boolean coSignEnabled = false;
    
    private String policyIdentifier;
    private String policyDescription;
	private String baseReference;
	
	private Map<String, String> bindValues;

    public SignatureOptions()
    {
        bindValues = new HashMap<String, String>();
    }

    public boolean isHash()
    {
        return hash;
    }

    public void setHash(boolean hash)
    {
        this.hash = hash;
    }

    public boolean isLocalFile()
    {
        return localFile;
    }

    public void setLocalFile(boolean localFile)
    {
        this.localFile = localFile;
    }

    public void setSwapToFile(boolean swapToFile)
    {
        this.swapToFile = swapToFile;
    }
    
    public boolean getSwapToFile()
    {
        return this.swapToFile;
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

    public InputStream getDataToSign()
    {
        return this.dataToSign;
    }

    public void setDataToSign(InputStream dataToSign)
    {
        this.dataToSign = dataToSign;
    }

    public boolean isCoSignEnabled()
    {
        return coSignEnabled;
    }

    public void setCoSignEnabled(boolean coSignEnabled)
    {
        this.coSignEnabled = coSignEnabled;
    }

    public String getPolicyIdentifier()
    {
        return policyIdentifier;
    }

    public void setPolicyIdentifier(String policyIdentifier)
    {
        this.policyIdentifier = policyIdentifier;
    }

    public String getPolicyDescription()
    {
        return policyDescription;
    }

    public void setPolicyDescription(String policyDescription)
    {
        this.policyDescription = policyDescription;
    }

    public String getXAdESBaseReference() {
		return this.baseReference;
	}
    
    public void setXAdESBaseReference(String baseRef) {
    	this.baseReference= baseRef;
	}

    public Map<String, String> getVisibleSignatureTextBindValues()
    {
        return bindValues;
    }
    
    public void setVisibleSignatureTextBindValues(Map<String, String> bindValues)
    {
        this.bindValues = bindValues;
    }
}
