package es.uji.security.crypto.raw;

import java.io.ByteArrayInputStream;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.X509Certificate;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.util.OS;
import es.uji.security.util.i18n.LabelManager;

public class RawSignatureFactory implements ISignFormatProvider
{
    public SignatureResult formatSignature(SignatureOptions signatureOptions)
            throws KeyStoreException, Exception
    {
        byte[] data = OS.inputStreamToByteArray(signatureOptions.getDataToSign());
        X509Certificate certificate = signatureOptions.getCertificate();
        PrivateKey privateKey = signatureOptions.getPrivateKey();
        Provider provider = signatureOptions.getProvider();

        Signature rsa = Signature.getInstance("SHA1withRSA", provider);

        SignatureResult signatureResult = new SignatureResult();

        if (certificate == null)
        {
            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERR_RAW_NOCERT"));

            return signatureResult;
        }

        if (privateKey == null)
        {
            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERR_RAW_NOKEY"));

            return signatureResult;
        }

        rsa.initSign(privateKey);
        rsa.update(data);

        byte[] res = rsa.sign();

        // Verification
        Signature rsa_vfy = Signature.getInstance("SHA1withRSA", provider);
        rsa_vfy.initVerify(certificate);
        rsa_vfy.initVerify(certificate.getPublicKey());
        rsa_vfy.update(data);

        if (res == null)
        {
            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERROR_RAW_SIGNATURE"));
        }
        else
        {
            signatureResult.setValid(true);
            signatureResult.setSignatureData(new ByteArrayInputStream(res));
        }

        return signatureResult;
    }
}
