package es.uji.security.crypto.openxades;

import java.io.ByteArrayInputStream;
import java.util.Properties;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.openxades.digidoc.SignedDoc;
import es.uji.security.crypto.openxades.digidoc.factory.DigiDocFactory;
import es.uji.security.crypto.openxades.digidoc.utils.ConfigManager;
import es.uji.security.util.ConfigHandler;
import es.uji.security.util.OS;

public class OpenXAdESCoSignatureFactory implements ISignFormatProvider
{
    private String signerRole = "UNSET";
    private String xadesFileName = "data.xml";
    private String xadesFileMimeType = "application/binary";

    public void setSignerRole(String srole)
    {
        signerRole = srole;
    }

    public void setXadesFileName(String filename)
    {
        xadesFileName = filename;
    }

    public void setXadesFileMimeType(String fmimetype)
    {
        xadesFileMimeType = fmimetype;
    }

    public SignatureResult formatSignature(SignatureOptions signatureOptions) throws Exception
    {
        byte[] data = OS.inputStreamToByteArray(signatureOptions.getDataToSign());

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
        SignedDoc sdoc = digFac.readSignedDoc(new ByteArrayInputStream(data));

        OpenXAdESSignatureFactory openXAdESSignatureFactory = new OpenXAdESSignatureFactory();
        openXAdESSignatureFactory.setSignerRole(signerRole);
        openXAdESSignatureFactory.setXadesFileName(xadesFileName);
        openXAdESSignatureFactory.setXadesFileMimeType(xadesFileMimeType);

        return openXAdESSignatureFactory.signDoc(sdoc, signatureOptions);
    }
}
