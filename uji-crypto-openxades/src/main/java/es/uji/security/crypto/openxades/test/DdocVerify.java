package es.uji.security.crypto.openxades.test;

import java.util.ArrayList;

import es.uji.security.crypto.openxades.digidoc.Signature;
import es.uji.security.crypto.openxades.digidoc.SignedDoc;
import es.uji.security.crypto.openxades.digidoc.factory.DigiDocFactory;
import es.uji.security.crypto.openxades.digidoc.utils.ConfigManager;
import es.uji.security.util.Base64;

public class DdocVerify
{

    /**
     * @param args
     */
    @SuppressWarnings("unchecked")
    public static void main(String[] args)
    {

        try
        {
            // String BASE = "/opt/projects-eclipse-3.2/ujiCrypto/etc/";
            String BASE = "/tmp/";

            // Leemos el fichero de configuracion
            ConfigManager.init(BASE + "jdigidoc.cfg");

            // TODO Auto-generated method stub
            SignedDoc sdoc;
            DigiDocFactory digFac = ConfigManager.instance().getDigiDocFactory();
            sdoc = digFac.readSignedDoc("/home/paul/x2.ddoc");

            System.out.println("\nContenido firmado: "
                    + new String(Base64.decode(sdoc.getLastDataFile().getBody())));
            Signature sig;

            for (int i = 0; i < sdoc.countSignatures(); i++)
            {
                System.out.println("Firma " + i);
                sig = sdoc.getSignature(i);

                System.out.println("  Firmado por: " + sig.getKeyInfo().getSubjectDN());
                System.out.println("  Información de timestamp: ");
                System.out.println("  Fecha: " + sig.getTimestampInfo(0).getTime());

                System.out.print("  Resultado de la verificación: ");

                ArrayList errs = sig.verify(sdoc, false, false);
                if (errs.size() == 0)
                {
                    System.out.println("OK!");
                }

                for (int j = 0; j < errs.size(); j++)
                {
                    System.out.println("Errores: " + errs.size());
                    System.out.println("Que es: " + errs.get(j));
                    System.out.println("ERROR!");
                }
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}
