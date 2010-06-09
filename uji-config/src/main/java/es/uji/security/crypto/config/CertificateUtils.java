package es.uji.security.crypto.config;


import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
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
     * @throws ConfigException 
     */
     public static X509Certificate[] getCertificateChain(X509Certificate cer) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, ConfigException{
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
    			throw new ConfigException(ex);
    		}
    	}
    	   	   
    	//Reversing the cert order to get CA_lvl3, CA_lvl2, CA_root.
    	res= new X509Certificate[vcertchain.size()];
    	if (res.length != 0){
    		res = new X509Certificate[res.length];
    		for (int i=0; i<res.length; i++){
    			res[res.length - (1 + i)] = vcertchain.get(i);
    		}
    	}
    	
    	return res;
    }
}
