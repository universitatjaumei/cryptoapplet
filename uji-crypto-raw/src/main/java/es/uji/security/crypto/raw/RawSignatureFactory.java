package es.uji.security.crypto.raw;

import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.X509Certificate;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.util.i18n.LabelManager;

public class RawSignatureFactory implements ISignFormatProvider
{
    private String _strerr = "";

    public byte[] formatSignature(SignatureOptions sigOpt) throws KeyStoreException, Exception
    {
        byte[] datos = sigOpt.getToSignByteArray();
        X509Certificate sCer = sigOpt.getCertificate();
        PrivateKey pk = sigOpt.getPrivateKey();
        Provider pv = sigOpt.getProvider();

        Signature rsa = Signature.getInstance("SHA1withRSA", pv);

        if (sCer == null)
        {
            _strerr = LabelManager.get("ERR_RAW_NOCERT");
            return null;
        }

        if (pk == null)
        {
            _strerr = LabelManager.get("ERR_RAW_NOKEY");
            return null;
        }

        rsa.initSign(pk);
        rsa.update(datos);

        byte[] res = rsa.sign();

        // Verification:
        Signature rsa_vfy = Signature.getInstance("SHA1withRSA");
        rsa_vfy.initVerify(sCer);
        rsa_vfy.initVerify(sCer.getPublicKey());
        rsa_vfy.update(datos);

        if (res == null)
        {
            _strerr = LabelManager.get("ERROR_RAW_SIGNATURE");
        }

        return res;
    }

    public String getError()
    {
        return _strerr;
    }
}
