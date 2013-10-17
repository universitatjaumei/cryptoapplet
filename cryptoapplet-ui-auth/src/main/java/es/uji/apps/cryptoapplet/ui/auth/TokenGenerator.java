package es.uji.apps.cryptoapplet.ui.auth;

import org.apache.commons.codec.binary.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class TokenGenerator
{
    private static final String SIGNATURE_ALGORITHM = "SHA512withRSA";

    private byte[] inputStreamToByteArray(InputStream in)
    {
        byte[] buffer = new byte[2048];
        int length = 0;

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try
        {
            while ((length = in.read(buffer)) >= 0)
            {
                baos.write(buffer, 0, length);
            }

            return baos.toByteArray();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public String generateToken(String tokenData) throws Exception
    {
        byte[] privateKeyData = inputStreamToByteArray(TokenGenerator.class.getClassLoader().getResourceAsStream("private.key"));

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privateKeyData);
        PrivateKey privateKey = keyFactory.generatePrivate(ks);

        Signature rsa = Signature.getInstance(SIGNATURE_ALGORITHM);
        rsa.initSign(privateKey);
        rsa.update(tokenData.getBytes());

        return Hex.encodeHexString(rsa.sign());
    }

    public boolean verifyToken(String tokenData, String signature)
    {
        try
        {
            byte[] publicKeyData = inputStreamToByteArray(TokenGenerator.class.getClassLoader().getResourceAsStream("public.key"));

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKeyData);
            PublicKey publicKey = keyFactory.generatePublic(ks);

            Signature validator = Signature.getInstance(SIGNATURE_ALGORITHM);
            validator.initVerify(publicKey);
            validator.update(tokenData.getBytes());

            return validator.verify(Hex.decodeHex(signature.toCharArray()));
        }
        catch (Exception e)
        {
            return false;
        }
    }

}
