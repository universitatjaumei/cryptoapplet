package es.uji.security.crypto.cms.test;


import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedGenerator;


import es.uji.security.crypto.cms.bc.MyCMSSignedDataGenerator;
import es.uji.security.util.Base64;



/**
 * A simple example that generates an attribute certificate.
 */
public class MySignedDataGeneratorTest
{
    public static void main(String[] args){
        byte[] hash= "01234567890123456789".getBytes();  

        MyCMSSignedDataGenerator gen = new MyCMSSignedDataGenerator();
        
        gen.addSigner(X509TestHelper.getClientPrivateKey(), 
                      X509TestHelper.getClientCert(), 
                      CMSSignedGenerator.DIGEST_SHA1);

        CMSProcessableByteArray cba = new CMSProcessableByteArray(hash);

        List<Certificate> certList = new ArrayList<Certificate>();

        // TODO: Add the intermediate CAs if we have them
        certList.add(X509TestHelper.getClientCert());

        try
        {
            CertStore certst = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");
            gen.addCertificatesAndCRLs(certst);
            gen.setHash(hash);

            CMSSignedData data = gen.generate(cba, Security.getProvider("BC"));
            
            System.out.println("Base 64 Result: " + new String(Base64.encode(data.getEncoded(), true)));
        }
        catch (Exception e)
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }    
}