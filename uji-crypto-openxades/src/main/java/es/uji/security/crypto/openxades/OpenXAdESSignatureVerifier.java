package es.uji.security.crypto.openxades;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Properties;

import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.openxades.digidoc.DigiDocException;
import es.uji.security.crypto.openxades.digidoc.Signature;
import es.uji.security.crypto.openxades.digidoc.SignedDoc;
import es.uji.security.crypto.openxades.digidoc.factory.DigiDocFactory;
import es.uji.security.crypto.openxades.digidoc.utils.ConfigManager;
import es.uji.security.util.ConfigHandler;

public class OpenXAdESSignatureVerifier
{
    @SuppressWarnings("unchecked")
    public VerificationResult verify(byte[] signedData)
    {
        VerificationResult verificationDetails = new VerificationResult();

        try
        {
            Properties prop = ConfigHandler.getProperties();

            if (prop != null)
            {
                ConfigManager.init(prop);
            }
            else
            {
                verificationDetails.setValid(false);
                verificationDetails.addError("Invalid OpenXAdES configuration");

                return verificationDetails;
            }

            DigiDocFactory digFac = ConfigManager.instance().getDigiDocFactory();
            SignedDoc sdoc = digFac.readSignedDoc(new ByteArrayInputStream(signedData));

            if (sdoc.countSignatures() == 0)
            {
                verificationDetails.setValid(false);
                verificationDetails.addError("No signatures found");

                return verificationDetails;
            }

            boolean confirmation = ConfigManager.instance().getProperty(
                    "DIGIDOC_DEMAND_OCSP_CONFIRMATION_ON_VERIFY").equals("true");

            ArrayList<String> allErrors = new ArrayList<String>();

            for (int i = 0; i < sdoc.countSignatures(); i++)
            {
                Signature sig = sdoc.getSignature(i);
                ArrayList errs = sig.verify(sdoc, false, confirmation);

                if (errs.size() > 0)
                {
                    for (int j = 0; j < errs.size(); j++)
                    {
                        allErrors.add(((DigiDocException) errs.get(j)).getMessage());
                    }
                }
            }

            if (allErrors.size() == 0)
            {
                verificationDetails.setValid(true);
            }
            else
            {
                verificationDetails.setValid(false);

                for (String e : allErrors)
                {
                    verificationDetails.addError(e);
                }
            }

            return verificationDetails;
        }
        catch (Exception e)
        {
            verificationDetails.setValid(false);
            verificationDetails.addError(e.getMessage());
            
            return verificationDetails;
        }
    }
}