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

package es.uji.security.crypto;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;

import javax.crypto.Cipher;

import sun.security.timestamp.HttpTimestamper;
import sun.security.timestamp.TSRequest;
import sun.security.timestamp.TSResponse;
import es.uji.security.util.asn1.DERObjectIdentifier;

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

    public static byte[] getMessageImprint(TSResponse response) throws IOException{

    	byte[] tok= response.getToken().getContentInfo().getContentBytes();

    	try{
    		int j=3; 
    		// Tok is the der encoded array 
    		// First a 30 81 TAM sequence and tam is indicated so 
    		// at position i=3 we must find an integer 0x02 

    		if (tok[j]!=0x02)
    			return null; 

    		// Now we must get the length of the integer and skip it 
    		j += tok[j+1] + 2;

    		// An oid with the tsa policy must be found.
    		if (tok[j]!=0x06)
    			return null; 
    	
    		// skip tsaPolicy OID length
    		j+= tok[j+1] + 2;

    		//Now four bytes of a double sequence: 
    		j+= 4; 

    		// And now we point to the hash algorith oid.
    		if (tok[j]!=0x06)
    			return null; 
   		    		
    		// skip hashalg OID length
    		j+= tok[j+1] + 2;

    		// And now we point to the hash itself.
    		if (tok[j]!=0x04)
    			return null; 

    		int l=tok[j+1];
    		byte[] hash= new byte[l];
    		System.arraycopy(tok, j+2, hash, 0, l);
    		return hash; 
    	}
    	catch(ArrayIndexOutOfBoundsException ai){
    		//Parsing failure, null will be returned.
    	}
    	return null;
    }

    public static Date getUTCTime(TSResponse response) throws IOException {
    	
    	DateFormat dfm = new SimpleDateFormat("yyyyMMddHHmmss");
    	dfm.setTimeZone(new SimpleTimeZone(0, "Z"));
   
    	byte[] tok= response.getToken().getContentInfo().getContentBytes();

    	try{
    		int j=3; 
    		// Tok is the der encoded array 
    		// First a 30 81 TAM sequence and tam is indicated so 
    		// at position i=3 we must find an integer 0x02 

    		if (tok[j]!=0x02)
    			return null; 

    		// Now we must get the length of the integer and skip it 
    		j += tok[j+1] + 2;

    		// An oid with the tsa policy must be found.
    		if (tok[j]!=0x06)
    			return null; 
 		

    		// skip tsaPolicy OID length
    		j+= tok[j+1] + 2;

    		//Now four bytes of a double sequence: 
    		j+= 4; 

    		// And now we point to the hash algorith oid.
    		if (tok[j]!=0x06)
    			return null; 

    		// skip hashalg OID length
    		j+= tok[j+1] + 2;

    		// And now we point to the hash itself.
    		if (tok[j]!=0x04)
    			return null; 
    		
    		// skip hash length and serial integer
    		j+= tok[j+1] + 2;
    		j+= tok[j+1] + 2;
    		
    		// And now we point to the time.
    		if (tok[j]!=0x18)
    			return null; 
    		
    		// The UTC generalized time.
    		String genTime= new String(tok,j+2,tok[j+1]);
    		return dfm.parse(genTime);
    	}
    	catch(ArrayIndexOutOfBoundsException ai){
    		//Parsing failure, null will be returned.
    	}
    	catch(ParseException pe){
    		//Parsing failure, null will be returned.
    	}
    	
    	return null;
    }

    /**
     * 
     * Verify the timeStamp token, this function is not enought verification, the certificate 
     * passed here must be checked against the ca trust anchor.
     * 
     * */
   
    public static boolean verify(X509Certificate cert, TSResponse response ) throws IOException
    {
    	return verify(cert, response, null, false,  "SHA-1" );
    }
    
    public static boolean verify(X509Certificate cert, TSResponse response, byte[] origData ) throws IOException
    {
    	return verify(cert, response, origData, true,  "SHA-1" );
    }
    public static boolean verify(X509Certificate cert, TSResponse response, byte[] origData, boolean verifyData,  String  signatureDigestAlgorithm) throws IOException
    { 	
    	byte[] pk9enc= response.getToken().getSignerInfos()[0].getAuthenticatedAttributes().getDerEncoding();
        byte[] ciphdig= response.getToken().getSignerInfos()[0].getEncryptedDigest(); 
        
        try {
        	//By now we only support RSA 
		    Cipher ciph= Cipher.getInstance("RSA");
		    ciph.init(Cipher.DECRYPT_MODE, cert);
		    
		    byte[] deciphdig= ciph.doFinal(ciphdig);
		           
	        MessageDigest messageDigest = MessageDigest.getInstance(signatureDigestAlgorithm);
            byte[] digest = messageDigest.digest(pk9enc);
            
            //Parse asn1 deciphered structure:
            /* 0   33: SEQUENCE {
               2    9:   SEQUENCE {
               4    5:     OBJECT IDENTIFIER sha1 (1 3 14 3 2 26)
              11    0:     NULL
                     :     }
              13   20:   OCTET STRING
                     :     B2 89 51 1E 57 C3 ED B9 2A EF 91 86 DE E8 FA A7
                     :     C4 9D EE 3A
                     :   }
            */
            // 4 bytes two sequences 
            int i=4; 
            if (deciphdig[i] != 0x06){ //OID
            	return false; 
            }
            String oid= DERObjectIdentifier.getOIDasString(deciphdig, i+2, deciphdig[i+1]);
            String hashAlg= DERObjectIdentifier.getHashAlgorithFromOID(oid);
            
            if ( ! hashAlg.equals("SHA1") && ! hashAlg.equals("SHA256")
            		&& ! hashAlg.equals("SHA384") && ! hashAlg.equals("SHA512") )
            {
            	return false; //Invalid algorithm (not supported). 
            }
            i+= deciphdig[i+1] + 2;

            if (deciphdig[i]!=0x04){
            	//Could be a NULL tag
            	i+= deciphdig[i+1] + 2;
            	//Now we must point to the hash
            	if (deciphdig[i]!=0x04){
            		return false;	
            	}
            }

            //The length must be the same: 
            if (digest.length != deciphdig[i+1]){
            	return false;
            }
            i+= 2;
         
            //We are pointing at the hash now, so we can compare it:
            for (int j=0; j<digest.length; j++){
            	if ( digest[j] !=  deciphdig[i+j]){
            		return false;
            	}
            }
            
            // Here we have checked the signature is correct.
            // Now check the message imprint.     
            if ( verifyData ){
            	messageDigest.reset();
            	byte[] oddig = messageDigest.digest(origData);
            	byte[] msgImp= getMessageImprint(response);
            	if (oddig.length != msgImp.length){
            		return false;
            	}

            	for (int j=0; j<oddig.length; j++){
            		if ( oddig[j] !=  msgImp[j]){
            			return false;
            		}
            	}
            }
                        
            return true; 
            
        } catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	
    	
    	return false; 
    }


    public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException, IOException
    {
    	try {
    		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

    		// get user password and file input stream
    		char[] password = "cryptoapplet".toCharArray();
    		FileInputStream fis= new FileInputStream("../uji.keystore");
    		ks.load(fis, password);
    		fis.close();

    		X509Certificate cert= (X509Certificate) ks.getCertificate("TSA1_ACCV");
    		TSResponse r= TimeStampFactory.getTimeStampResponse("http://tss.accv.es:8318/tsa", "test".getBytes(), true);

    		System.out.print("Successful verification: ");
    		System.out.println(" " + TimeStampFactory.verify(cert, r, "test".getBytes()));
    		
    		System.out.print("Bad data digest verification: ");
    		System.out.println(" " + TimeStampFactory.verify(cert, r, "testx".getBytes()));

    		System.out.print("No original data check verification: ");
    		System.out.println(" " + TimeStampFactory.verify(cert, r, null, false, "SHA-1"));
    	}
    	catch(Exception e){
    		e.printStackTrace();
    	}
    }
}
