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

package es.uji.security.crypto.timestamp;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public class TimeStampFactory
{
	public static TSResponse getTimeStampResponse(String strUrl, byte[] data, boolean calculateDigest) throws NoSuchAlgorithmException, IOException, SignatureException
    {
		return getTimeStampResponse(strUrl, data, calculateDigest, "SHA-1");
    }
	public static TSResponse getTimeStampResponse(String strUrl, byte[] data, boolean calculateDigest, String digestAlgorithm) throws NoSuchAlgorithmException, IOException, SignatureException
    {
        HttpTimestamper httpTimestamper = new HttpTimestamper(strUrl);
        
        byte[] digest = data;
      
        if (calculateDigest)
        {
            MessageDigest messageDigest = MessageDigest.getInstance(digestAlgorithm);
            digest = messageDigest.digest(data);  
        }
        
        
        TSRequest request = new TSRequest(digest, digestAlgorithm );
        request.requestCertificate(true);
        
        TSResponse response = httpTimestamper.generateTimestamp(request); 
        
        return response;
    }
    
    public static byte[] getTimeStamp(String tsaURL, byte[] data, boolean calculateDigest) throws NoSuchAlgorithmException, IOException, SignatureException
    {
        TSResponse response = getTimeStampResponse(tsaURL, data, calculateDigest);
        return response.getEncodedToken();
    }
}
