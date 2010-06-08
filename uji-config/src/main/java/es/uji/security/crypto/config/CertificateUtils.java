package es.uji.security.crypto.config;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Vector;

public class CertificateUtils
{
    public static String getCn(X509Certificate certificate)
    {
        String cn = "";
        
        if (certificate != null)
        {
            String cnField = certificate.getSubjectDN().getName();

            if (cnField != null)
            {
                String[] fields = cnField.split(",");

                for (String f : fields)
                {
                    if (f.trim().startsWith("CN="))
                    {
                        cn = f.trim().substring(3);
                    }
                }
            }
        }
        
        return cn;
    }
    
    /**
     * Receives a certificate and looks for the certificate chain with ca certificates indicated in the config file. 
     * 
     * 
     * @return X509Certificate[] the certificate chain of given certificate or null if the chain is not found. 
     * @throws IOException 
     * @throws NoSuchAlgorithmException 
     * @throws CertificateException 
     * @throws KeyStoreException 
     */
     public static X509Certificate[] getCertificateChain(X509Certificate cer) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException{
    	ConfigManager cfm= ConfigManager.getInstance();
    	//First we must get a copy of each certificate in configuration: 
    	//Testing with the CA certs. 
    	
    	Vector<X509Certificate> vcertchain= new Vector<X509Certificate>();
    	HashMap<String, X509Certificate> certmap= new HashMap<String, X509Certificate>();
    	
    	int n= Integer.parseInt(cfm.getProperty("DIGIDOC_CA_CERTS","0"));
    	String scert="";
    	X509Certificate xcert; 
    	X509Certificate[] res;
    	
        	
    	//Let's read the certificates. 
    	for (int i=1; i<=n; i++){
    		scert= cfm.getProperty("DIGIDOC_CA_CERT" + i);
    		xcert= ConfigManager.readCertificate(scert);
    		certmap.put(xcert.getSubjectDN().toString(), xcert);
    	}
    	
    	X509Certificate auxcert= cer;
    	String auxIssuerDN= auxcert.getIssuerDN().toString();
    	X509Certificate auxCertIssuer= certmap.get(auxIssuerDN);
    	
    	while (auxCertIssuer != null && !auxcert.getIssuerDN().toString().equals(auxcert.getSubjectDN().toString())){
    		try {
    			auxcert.verify(auxCertIssuer.getPublicKey());
    			auxcert= auxCertIssuer;
    			auxIssuerDN= auxCertIssuer.getIssuerDN().toString();
    			auxCertIssuer= certmap.get(auxIssuerDN);
    			vcertchain.add(auxcert);
    		}
    		catch (Exception ex){
    			ex.printStackTrace();
    			return null;
    		}
    	}
    	   	   
    	res= new X509Certificate[vcertchain.size()];
    	vcertchain.toArray(res);
    	return res;
    }
          
     //Testing porpouses, this should go to uji-tests.
     public static void main(String args[]) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException{ 	 
    	 InputStream certificateStream = new FileInputStream("/home/paul/mio.pem");
    	 CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
         X509Certificate certificate = (X509Certificate) certificateFactory
                 .generateCertificate(certificateStream);
         certificateStream.close();
    
         X509Certificate[] xchain= CertificateUtils.getCertificateChain(certificate);
         if (xchain != null){
        	 for (int i=0; i<xchain.length; i++){
        		 System.out.println(xchain[i].getSubjectDN());
        	 }
         }
         else{
        	 System.out.println("xchain is null");
         }
     }
}
