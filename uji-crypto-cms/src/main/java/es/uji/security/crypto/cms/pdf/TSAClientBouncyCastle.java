package es.uji.security.crypto.cms.pdf;

import es.uji.security.crypto.timestamp.TimeStampFactory;

/**
 * 
 * Time Stamp Authority Client interface implementation using Bouncy Castle
 * 
 * org.bouncycastle.tsp package.
 * 
 * <p>
 * 
 * Created by Aiken Sam, 2006-11-15, refactored by Martin Brunecky, 07/15/2007
 * 
 * for ease of subclassing.
 * 
 * </p>
 */

public class TSAClientBouncyCastle implements TSAClient
{
    protected String tsaURL;
    protected String tsaUsername;
    protected String tsaPassword;
    protected int tokSzEstimate;

    public TSAClientBouncyCastle(String url)
    {
        this(url, null, null, 4096);
        Integer counter = 1; // boxing
        int counter2 = counter; // unboxing
    }

    public TSAClientBouncyCastle(String url, String username, String password)
    {
        this(url, username, password, 4096);
    }

    /**
     * 
     * Constructor.
     * 
     * Note the token size estimate is updated by each call, as the token
     * 
     * size is not likely to change (as long as we call the same TSA using
     * 
     * the same imprint length).
     * 
     * @param url
     *            String - Time Stamp Authority URL (i.e. "http://tsatest1.digistamp.com/TSA")
     * 
     * @param username
     *            String - user(account) name
     * 
     * @param password
     *            String - password
     * 
     * @param tokSzEstimate
     *            int - estimated size of received time stamp token (DER encoded)
     */

    public TSAClientBouncyCastle(String url, String username, String password, int tokSzEstimate)
    {
        this.tsaURL = url;
        this.tsaUsername = username;
        this.tsaPassword = password;
        this.tokSzEstimate = tokSzEstimate;
    }

    /**
     * 
     * Get the token size estimate.
     * 
     * Returned value reflects the result of the last succesfull call, padded
     * 
     * @return int
     */

    public int getTokenSizeEstimate()
    {
        return tokSzEstimate;
    }

    public byte[] getTimeStampToken(PdfPKCS7TSA caller, byte[] imprint) throws Exception
    {
        return getTimeStampToken(imprint);
    }

    /**
     * 
     * Get timestamp token - Bouncy Castle request encoding / decoding layer
     */

    protected byte[] getTimeStampToken(byte[] imprint) throws Exception
    {        
        return TimeStampFactory.getTimeStampResponse(tsaURL, imprint, false).getEncodedToken();
    }
}
