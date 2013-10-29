package es.uji.security.crypto.openxades;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;

import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.config.ConfigManager;
import es.uji.security.crypto.openxades.digidoc.DigiDocException;
import es.uji.security.crypto.openxades.digidoc.Signature;
import es.uji.security.crypto.openxades.digidoc.SignedDoc;
import es.uji.security.crypto.openxades.digidoc.factory.DigiDocFactory;
import es.uji.security.crypto.openxades.digidoc.factory.FactoryManager;

public class OpenXAdESSignatureVerifier
{
    @SuppressWarnings("unchecked")
    public VerificationResult verify(byte[] signedData)
    {
        VerificationResult verificationDetails = new VerificationResult();

        try
        {
            ConfigManager conf = ConfigManager.getInstance();

            DigiDocFactory digFac = FactoryManager.getDigiDocFactory();
            SignedDoc sdoc = digFac.readSignedDoc(new ByteArrayInputStream(signedData));

            if (sdoc.countSignatures() == 0)
            {
                verificationDetails.setValid(false);
                verificationDetails.addError("No signatures found");

                return verificationDetails;
            }

            boolean confirmation = conf.getProperty("DIGIDOC_DEMAND_OCSP_CONFIRMATION_ON_VERIFY")
                    .equals("true");

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