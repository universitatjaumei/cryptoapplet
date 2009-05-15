package es.uji.security.crypto;

import java.security.Provider;
import java.security.Security;


public class AbstractSignatureFactory {

	/**
	 * Initialize providers. 
	 * By the time, only BC prov.
	 * */
	public void initialize(){
		
		Provider bcProv, capiProv; 
		
		
		System.out.println("Pazamos! "); 
		
		if (Security.getProvider("BC") == null)
		{
			try{
				bcProv = (Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").newInstance();
				Security.addProvider(bcProv);
			}
			catch(Exception e){
				e.printStackTrace();
			}
		}
		
		/**
    	 * Initialize MSCAPI provider here. It will be used through  
    	 * its associated keystore.
    	 * */ 
    	if (Security.getProvider("UJI-MSCAPI") == null)
    	{
    		try{
    			System.out.println("Intentamos instalar MS-CAPI");
				capiProv = (Provider) Class.forName("es.uji.security.keystore.mscapi.MSCAPIProvider").newInstance();
				Security.addProvider(capiProv);
				System.out.println("Provider: " + capiProv.getName());
			}
			catch(Exception e){
				e.printStackTrace();
			}
    	}
	}
}
