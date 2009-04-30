package es.uji.security.crypto.openxades.test;

import java.io.File;

import es.uji.security.crypto.openxades.digidoc.SignedDoc;
import es.uji.security.crypto.openxades.digidoc.factory.DigiDocFactory;
import es.uji.security.crypto.openxades.digidoc.utils.ConfigManager;

public class ReadWriteTest
{
    public static void main(String[] args)
    {
        try
        {

            ConfigManager.init("etc/jdigidoc.cfg.local");
            DigiDocFactory digFac = ConfigManager.instance().getDigiDocFactory();

            SignedDoc sdoc = digFac.readSignedDoc("/home/paul/x.ddoc");
            // sdoc.toXML();
            // sdoc.writeToFile(new File("/home/paul/x.ddoc"));
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}
