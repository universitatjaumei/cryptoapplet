package es.uji.security.crypto;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SignatureOptions
{
    // General options
    
    private X509Certificate certificate;
    private PrivateKey privateKey;
    private Provider provider;
    private InputStream dataToSign;

    private boolean hash = false;
    private boolean localFile = false;
    private boolean swapToFile = false;
    private boolean coSignEnabled = false;
    private boolean enveloped = true;
    
    // XML options
    
    private String policyIdentifier;
    private String policyDescription;
	private List<String> references;
	
	// PDF options
	
	private Map<String, String> bindValues;
	private String reason;
	private String location;
	private String contact;
	private Boolean timestamping;
	private String tsaURL;
	private Boolean visibleSignature;
	private String visibleSignatureType;
	private Integer visibleAreaX;
    private Integer visibleAreaY;
    private Integer visibleAreaX2;
    private Integer visibleAreaY2;
    private Integer visibleAreaPage;
    private Integer visibleAreaTextSize;
    private String visibleAreaImgFile;
    private String visibleAreaRepeatAxis;
    private String visibleAreaTextPattern;

    public SignatureOptions()
    {
        bindValues = new HashMap<String, String>();
        references = new ArrayList<String>();
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

    public Map<String, String> getVisibleSignatureTextBindValues()
    {
        return bindValues;
    }
    
    public void setVisibleSignatureTextBindValues(Map<String, String> bindValues)
    {
        this.bindValues = bindValues;
    }

    public List<String> getReferences()
    {
        return references;
    }

    public void setReferences(List<String> references)
    {
        this.references = references;
    }

    public void addReference(String reference)
    {
        if (this.references != null)
        {
            this.references.add(reference);
        }
    }

    public void clearReferences()
    {
        this.references.clear();
    }
    
    public Map<String, String> getBindValues()
    {
        return bindValues;
    }

    public void setBindValues(Map<String, String> bindValues)
    {
        this.bindValues = bindValues;
    }

    public String getReason()
    {
        return reason;
    }

    public void setReason(String reason)
    {
        this.reason = reason;
    }

    public String getLocation()
    {
        return location;
    }

    public void setLocation(String location)
    {
        this.location = location;
    }

    public String getContact()
    {
        return contact;
    }

    public void setContact(String contact)
    {
        this.contact = contact;
    }

    public Boolean isTimestamping()
    {
        return timestamping;
    }

    public void setTimestamping(Boolean timestamping)
    {
        this.timestamping = timestamping;
    }

    public String getTsaURL()
    {
        return tsaURL;
    }

    public void setTsaURL(String tsaURL)
    {
        this.tsaURL = tsaURL;
    }

    public Boolean isVisibleSignature()
    {
        return visibleSignature;
    }

    public void setVisibleSignature(Boolean visibleSignature)
    {
        this.visibleSignature = visibleSignature;
    }

    public String getVisibleSignatureType()
    {
        return visibleSignatureType;
    }

    public void setVisibleSignatureType(String visibleSignatureType)
    {
        this.visibleSignatureType = visibleSignatureType;
    }

    public Integer getVisibleAreaX()
    {
        return visibleAreaX;
    }

    public void setVisibleAreaX(Integer visibleAreaX)
    {
        this.visibleAreaX = visibleAreaX;
    }

    public Integer getVisibleAreaY()
    {
        return visibleAreaY;
    }

    public void setVisibleAreaY(Integer visibleAreaY)
    {
        this.visibleAreaY = visibleAreaY;
    }

    public Integer getVisibleAreaX2()
    {
        return visibleAreaX2;
    }

    public void setVisibleAreaX2(Integer visibleAreaX2)
    {
        this.visibleAreaX2 = visibleAreaX2;
    }

    public Integer getVisibleAreaY2()
    {
        return visibleAreaY2;
    }

    public void setVisibleAreaY2(Integer visibleAreaY2)
    {
        this.visibleAreaY2 = visibleAreaY2;
    }

    public Integer getVisibleAreaPage()
    {
        return visibleAreaPage;
    }

    public void setVisibleAreaPage(Integer visibleAreaPage)
    {
        this.visibleAreaPage = visibleAreaPage;
    }

    public Integer getVisibleAreaTextSize()
    {
        return visibleAreaTextSize;
    }

    public void setVisibleAreaTextSize(Integer visibleAreaTextSize)
    {
        this.visibleAreaTextSize = visibleAreaTextSize;
    }

    public String getVisibleAreaImgFile()
    {
        return visibleAreaImgFile;
    }

    public void setVisibleAreaImgFile(String visibleAreaImgFile)
    {
        this.visibleAreaImgFile = visibleAreaImgFile;
    }

    public String getVisibleAreaRepeatAxis()
    {
        return visibleAreaRepeatAxis;
    }

    public void setVisibleAreaRepeatAxis(String visibleAreaRepeatAxis)
    {
        this.visibleAreaRepeatAxis = visibleAreaRepeatAxis;
    }

    public String getVisibleAreaTextPattern()
    {
        return visibleAreaTextPattern;
    }

    public void setVisibleAreaTextPattern(String visibleAreaTextPattern)
    {
        this.visibleAreaTextPattern = visibleAreaTextPattern;
    }

    public boolean isEnveloped()
    {
        return enveloped;
    }

    public void setEnveloped(boolean enveloped)
    {
        this.enveloped = enveloped;
    }
}
