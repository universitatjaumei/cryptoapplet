package es.uji.security.keystore.dnie;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;


public class Dnie {

	public Dnie(){	
	 //nothing to do 	
	}
	
	public boolean isPresent(){
	   try{
            
		   System.out.println("Obtenido path " + getPkcs11FilePath());
		   
		   ByteArrayInputStream in= new ByteArrayInputStream(("name = DNIE-Pres\r" +
                               "library = " + getPkcs11FilePath()  + "\r\nslot=1\r\n").getBytes());
         
            Provider _pk11provider = new sun.security.pkcs11.SunPKCS11(in);
            Security.addProvider(_pk11provider);
            KeyStore _p11KeyStore = KeyStore.getInstance("PKCS11", _pk11provider);

            // Si pasamos de aquí el dnie está insertado.
            Security.removeProvider(_pk11provider.getName());
            System.out.println("Saliendo true ...");
            return true;
       }
       catch(KeyStoreException ex){
    	   // El dni no esta insertado!
    	   System.out.println("Saliendo false ...");
    	   return false;
       } 
       catch (ProviderException ex)
       {
    	   System.out.println("Saliendo false por el ProviderException...");   
    	   return false;
       }
       catch (Exception ex)
       {
    	   System.out.println("Saliendo false por el Exception...");  
    	   return false;
       }
 	}
	
	public String getPkcs11FilePath(){
		String[] strFiles = {"/usr/lib/opensc-pkcs11.so",
							 "/usr/local/lib/opensc-pkcs11.so",
							 "/lib/opensc-pkcs11.so",
							 "C:\\WINDOWS\\system32\\UsrPkcs11.dll"};
		
		for ( int i=0; i<strFiles.length; i++ ){
			File f= new File(strFiles[i]);
			if (f.exists()){
				return f.getAbsolutePath();
			}
		}
		
		return null;
	} 
	
	public InputStream getDnieConfigInputStream(){
		ByteArrayInputStream in= new ByteArrayInputStream(("name = DNIE-Pres\r" +
                "library = " + getPkcs11FilePath()  + "\r\nslot=1\r\n").getBytes());
		return in;
	}
}
