package es.uji.security.keystore.dnie;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;

import javax.swing.JOptionPane;

import org.apache.log4j.Logger;

import es.uji.security.keystore.IKeyStore;
import es.uji.security.keystore.pkcs11.PKCS11KeyStore;
import es.uji.security.util.i18n.LabelManager;

public class Dnie
{
    private Logger log = Logger.getLogger(Dnie.class);
    
    public boolean isPresent()
    {
        boolean dnieInserted = false;
        
        try
        {
            System.out.println("Obtenido path " + getPkcs11FilePath());

            ByteArrayInputStream in = new ByteArrayInputStream(("name = DNIE-Pres\r" + "library = "
                    + getPkcs11FilePath() + "\r\nslot=1\r\n").getBytes());

            Provider _pk11provider = new sun.security.pkcs11.SunPKCS11(in);
            Security.addProvider(_pk11provider);
            KeyStore.getInstance("PKCS11", _pk11provider);

            // Si pasamos de aquí el dnie está insertado.
            Security.removeProvider(_pk11provider.getName());
            System.out.println("Saliendo true ...");
            
            dnieInserted = true;
            
            log.debug("DNIe is now accesible");            
        }
        catch (Exception e)
        {
            log.debug("DNIe is not inserted or it can not be loaded");
        }
        
        return dnieInserted;
    }

    public String getPkcs11FilePath()
    {
        String[] systemLibraryList = { "/usr/lib/opensc-pkcs11.so", "/usr/local/lib/opensc-pkcs11.so",
                "/lib/opensc-pkcs11.so", "C:\\WINDOWS\\system32\\UsrPkcs11.dll" };

        for (String file : systemLibraryList)
        {
            File f = new File(file);
            
            if (f.exists())
            {
                return f.getAbsolutePath();
            }
        }

        return null;
    }

    public InputStream getDnieConfigInputStream()
    {
        ByteArrayInputStream in = new ByteArrayInputStream(("name = DNIE-Pres\r" + "library = "
                + getPkcs11FilePath() + "\r\nslot=1\r\n").getBytes());
        return in;
    }

    /**
     * This method tries to initialize the spanish dnie. If the browser is Internet Explorer, 
     * we can rely on CryptoAPI to deal with this. Nothing happens if it is not plugged.
     */
    
    public IKeyStore initDnie(char[] password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, Exception
    {
        IKeyStore keystoreDNIe = null;
        
        Dnie dnie = new Dnie();

        if (dnie.isPresent())
        {
            keystoreDNIe = (IKeyStore) new PKCS11KeyStore(dnie.getDnieConfigInputStream(), null, false);
            
            // We let then three password attempts
            for (int i = 0; i < 3; i++)
            {
                 try
                 {
                     keystoreDNIe.load(password);
                 }
                 catch (Exception e)
                 {
                     ByteArrayOutputStream os = new ByteArrayOutputStream();
                     PrintStream ps = new PrintStream(os);
                     e.printStackTrace(ps);
                     String stk = new String(os.toByteArray()).toLowerCase();

                     if (stk.indexOf("incorrect") > -1)
                     {
                         JOptionPane.showMessageDialog(null, LabelManager.get("ERROR_INCORRECT_DNIE_PWD"), "", JOptionPane.ERROR_MESSAGE);
                     }
                     else
                     {
                         JOptionPane.showMessageDialog(null, LabelManager.get("ERROR_UNKNOWN"), "", JOptionPane.ERROR_MESSAGE);
                     }
                 }
            }
        }
        
        return keystoreDNIe;
    }
}
