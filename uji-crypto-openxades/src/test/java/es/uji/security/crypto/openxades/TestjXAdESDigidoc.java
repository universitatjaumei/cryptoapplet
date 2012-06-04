package es.uji.security.crypto.openxades;

import java.io.FileInputStream;

import org.junit.Test;

import es.uji.security.crypto.BaseCryptoAppletTest;
import es.uji.security.crypto.ConfigManager;
import es.uji.security.crypto.openxades.digidoc.SignedDoc;
import es.uji.security.crypto.openxades.digidoc.factory.DigiDocFactory;
import es.uji.security.crypto.openxades.digidoc.factory.FactoryManager;

public class TestjXAdESDigidoc extends BaseCryptoAppletTest
{
    @Test
    public void jXAdESDigidoc() throws Exception
    {
        ConfigManager conf = ConfigManager.getInstance();

        DigiDocFactory digFac = FactoryManager.getDigiDocFactory();
        SignedDoc signedDoc = digFac.readSignedDoc(new FileInputStream(
                "src/main/resources/out-digidoc-openxades-2.xml"));
        
        System.out.println(signedDoc.countSignatures());
        System.out.println(signedDoc.toXML());
    }
}
