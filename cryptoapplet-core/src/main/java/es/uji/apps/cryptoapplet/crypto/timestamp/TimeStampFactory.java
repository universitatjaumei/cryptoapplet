/*
 * 
   The data is:
   TSTInfo ::= SEQUENCE  {
   version                      INTEGER  { v1(1) },
   policy                       TSAPolicyId,
   messageImprint               MessageImprint,
     -- MUST have the same value as the similar field in
     -- TimeStampReq
   serialNumber                 INTEGER,
    -- Time-Stamping users MUST be ready to accommodate integers
    -- up to 160 bits.
   genTime                      GeneralizedTime,
   ...
   
   <30 81 A4>                                  
   0  164: SEQUENCE {                           
    <02 01>                                     
   3    1:   INTEGER 1                          
    <06 0C>                                     
   6   12:   OBJECT IDENTIFIER '1 3 6 1 4 1 8149 3 2 1 1 0' //tsaPolicy
    <30 1F>                                                
  20   31:   SEQUENCE {                                    
    <30 07>                                                
  22    7:     SEQUENCE {                                  
    <06 05>                                                
  24    5:       OBJECT IDENTIFIER sha1 (1 3 14 3 2 26)    
         :       }                                         
    <04 14>                                                
  31   20:     OCTET STRING                                
         :       A9 4A 8F E5 CC B1 9B A6 1C 4C 08 73 D3 91 E9 87
         :       98 2F BB D3                                    
         :     }                                                
    <02 03>                                                     
  53    3:   INTEGER 6455515                                    
    <18 0F>                                                     
  58   15:   GeneralizedTime 28/05/2009 12:26:13 GMT            
 */

/**
 * TODO: We must check the verification and parsing errors. The correct will be to define a 
 *       exception hierarchy. By the time, the parsing methods returns null and the verification
 *       methods false if something happens. 
 * 
 */

package es.uji.apps.cryptoapplet.crypto.timestamp;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;

import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

public class TimeStampFactory
{
    public static TimeStampResponse getTimeStampResponse(String strUrl, byte[] data,
            boolean calculateDigest) throws Exception
    {
        return getTimeStampResponse(strUrl, data, calculateDigest, "SHA-1");
    }

    public static TimeStampResponse getTimeStampResponse(String strUrl, byte[] data,
            boolean calculateDigest, String digestAlgorithm) throws Exception
    {
        TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
        tsqGenerator.setCertReq(true);

        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        TimeStampRequest request = tsqGenerator.generate(X509ObjectIdentifiers.id_SHA1.getId(),
                data, nonce);

        byte[] requestBytes = request.getEncoded();

        byte[] respBytes = getTSAResponse(strUrl, requestBytes);
        TimeStampResponse response = new TimeStampResponse(respBytes);
        // validate communication level attributes (RFC 3161 PKIStatus)
        response.validate(request);
        return response;
    }

    public static byte[] getTimeStamp(String strUrl, byte[] data, boolean calculateDigest,
            String digestAlgorithm) throws Exception
    {
        TimeStampResponse response = getTimeStampResponse(strUrl, data, calculateDigest,
                digestAlgorithm);

        PKIFailureInfo failure = response.getFailInfo();

        int value = (failure == null) ? 0 : failure.intValue();

        if (value != 0)
        {
            // @todo: Translate value of 15 error codes defined by PKIFailureInfo to string
            throw new Exception("Invalid TSA '" + strUrl + "' response, code " + value);

        }

        // @todo: validate the time stap certificate chain (if we want
        // assure we do not sign using an invalid timestamp).
        // extract just the time stamp token (removes communication status info)

        TimeStampToken tsToken = response.getTimeStampToken();

        if (tsToken == null)
        {
            throw new Exception("TSA '" + strUrl + "' failed to return time stamp token");
        }

        TimeStampTokenInfo info = tsToken.getTimeStampInfo(); // to view details

        byte[] encoded = tsToken.getEncoded();
        long stop = System.currentTimeMillis();

        // Update our token size estimate for the next call (padded to be safe)

        return encoded;
    }

    private static byte[] getTSAResponse(String tsaURL, byte[] requestBytes) throws Exception
    {
        URL url = new URL(tsaURL);
        URLConnection tsaConnection = (URLConnection) url.openConnection();
        tsaConnection.setDoInput(true);
        tsaConnection.setDoOutput(true);
        tsaConnection.setUseCaches(false);
        tsaConnection.setRequestProperty("Content-Type", "application/timestamp-query");
        // tsaConnection.setRequestProperty("Content-Transfer-Encoding", "base64");
        tsaConnection.setRequestProperty("Content-Transfer-Encoding", "binary");

        OutputStream out = tsaConnection.getOutputStream();
        out.write(requestBytes);
        out.close();

        // Get TSA response as a byte array

        InputStream inp = tsaConnection.getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        byte[] buffer = new byte[1024];
        int bytesRead = 0;

        while ((bytesRead = inp.read(buffer, 0, buffer.length)) >= 0)
        {
            baos.write(buffer, 0, bytesRead);
        }

        byte[] respBytes = baos.toByteArray();

        String encoding = tsaConnection.getContentEncoding();

        if (encoding != null && encoding.equalsIgnoreCase("base64"))
        {
            sun.misc.BASE64Decoder dec = new sun.misc.BASE64Decoder();
            respBytes = dec.decodeBuffer(new String(respBytes));
        }

        return respBytes;

    }
}
