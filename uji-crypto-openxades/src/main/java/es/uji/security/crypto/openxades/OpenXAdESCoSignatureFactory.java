package es.uji.security.crypto.openxades;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Properties;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
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
    private String _sterr = "";

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

    public InputStream formatSignature(SignatureOptions sigOpt) throws Exception
    {

        InputStream res;

        byte[] toSign = OS.inputStreamToByteArray(sigOpt.getToSignInputStream());
        X509Certificate sCer = sigOpt.getCertificate();
        PrivateKey pk = sigOpt.getPrivateKey();
        Provider pv = sigOpt.getProvider();

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
        SignedDoc sdoc = digFac.readSignedDoc(new ByteArrayInputStream(toSign));

        OpenXAdESSignatureFactory xsf = new OpenXAdESSignatureFactory();
        xsf.setSignerRole(signerRole);
        xsf.setXadesFileName(xadesFileName);
        xsf.setXadesFileMimeType(xadesFileMimeType);
       
        res = xsf.signDoc(sdoc, sigOpt);

        _sterr = xsf.getError();

        return res;
    }

    public String getError()
    {
        return _sterr;
    }
}
