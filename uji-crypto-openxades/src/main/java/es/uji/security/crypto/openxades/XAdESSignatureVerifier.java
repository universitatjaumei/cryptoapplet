package es.uji.security.crypto.openxades;

import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Properties;
import java.util.Vector;

import es.uji.security.crypto.openxades.digidoc.DigiDocException;
import es.uji.security.crypto.openxades.digidoc.Signature;
import es.uji.security.crypto.openxades.digidoc.SignedDoc;
import es.uji.security.crypto.openxades.digidoc.factory.DigiDocFactory;
import es.uji.security.crypto.openxades.digidoc.utils.ConfigManager;
import es.uji.security.util.ConfigHandler;
import es.uji.security.util.i18n.LabelManager;

public class XAdESSignatureVerifier
{

    public XAdESSignatureVerifier()
    {

    }

    public String[] verifyUrl(String strUrl)
    {
        try
        {

            URL url = new URL(strUrl);
            URLConnection uc = url.openConnection();
            uc.connect();
            InputStream in = uc.getInputStream();
            return verify(in);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return new String[] { e.getMessage() };
        }
    }

    public String[] verify(InputStream in)
    {

        try
        {
            Properties prop = ConfigHandler.getProperties();
            if (prop != null)
            {
                ConfigManager.init(prop);
            }
            else
            {
                return null;
            }

            DigiDocFactory digFac = ConfigManager.instance().getDigiDocFactory();
            SignedDoc sdoc = digFac.readSignedDoc(in);

            Signature sig;
            boolean confirmation = ConfigManager.instance().getProperty(
                    "DIGIDOC_DEMAND_OCSP_CONFIRMATION_ON_VERIFY").equals("true");
            boolean isvalid = true;
            Vector<String> outErrs = new Vector<String>();

            System.out.println("Let's go!");
            for (int i = 0; i < sdoc.countSignatures(); i++)
            {
                sig = sdoc.getSignature(i);
                ArrayList errs = sig.verify(sdoc, false, confirmation);

                if (errs.size() != 0)
                {
                    isvalid = false;

                }

                for (int j = 0; j < errs.size(); j++)
                {
                    outErrs.add(((DigiDocException) errs.get(j)).getMessage());
                }
            }
            if (sdoc.countSignatures() == 0)
            {
                return new String[] { "No signatures found" };
            }
            else if (isvalid)
            {
                return null;
            }
            else
            {
                if (outErrs.size() != 0)
                {
                    String[] res = new String[outErrs.size()];
                    outErrs.toArray(res);
                    return res;
                }
                else
                {
                    return new String[] { "Unexpected Error!" };
                }
            }
        }

        catch (Exception e)
        {
            e.printStackTrace();
            return new String[] { e.getMessage() };
        }
    }
}
