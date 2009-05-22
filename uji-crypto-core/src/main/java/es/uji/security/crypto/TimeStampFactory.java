package es.uji.security.crypto;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import sun.security.timestamp.HttpTimestamper;
import sun.security.timestamp.TSRequest;
import sun.security.timestamp.TSResponse;

import es.uji.security.util.Base64;

public class TimeStampFactory
{
    public static TSResponse getTimeStampResponse(String strUrl, byte[] data, boolean calculateDigest) throws NoSuchAlgorithmException, IOException, SignatureException
    {
        HttpTimestamper httpTimestamper = new HttpTimestamper(strUrl);
        
        byte[] digest = data;
        
        if (calculateDigest)
        {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
            digest = messageDigest.digest(data);
        }

        TSRequest request = new TSRequest(digest, "SHA-1");
        request.requestCertificate(false);
        
        TSResponse response = httpTimestamper.generateTimestamp(request); 
        
        response.getToken().verify();        

        return response;
    }
    
    public static byte[] getTimeStamp(String tsaURL, byte[] data, boolean calculateDigest) throws NoSuchAlgorithmException, IOException, SignatureException
    {
        TSResponse response = getTimeStampResponse(tsaURL, data, calculateDigest); 

        return response.getEncodedToken();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException, IOException
    {
        System.out.println(new String(Base64.encode(TimeStampFactory.getTimeStamp("http://tss.accv.es:8318/tsa", "test".getBytes(), true))));
        System.out.println(TimeStampFactory.getTimeStampResponse("http://tss.accv.es:8318/tsa", "test".getBytes(), true).getToken());
    }
}
