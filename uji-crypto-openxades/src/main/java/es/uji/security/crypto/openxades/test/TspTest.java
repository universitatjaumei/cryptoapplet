package es.uji.security.crypto.openxades.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.*;
import java.io.*;
import java.util.*;
import java.math.BigInteger;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import org.bouncycastle.cms.*;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.jce.provider.*;

import es.uji.security.util.HexDump;

public class TspTest
{

    public static void Mydecrypt(byte[] data, RSAPublicKey key) throws Exception
    {
        HexDump h = new HexDump();
        BigInteger msj = new BigInteger(1, data);
        BigInteger mod = key.getModulus();
        BigInteger exp = key.getPublicExponent();

        BigInteger aux = msj.modPow(exp, mod);

        System.out.println("Descifrado: " + h.xdump(aux.toByteArray()) + "   len: "
                + aux.toByteArray().length);

    }

    /**
     * @param args
     */
    public static void main(String[] args)
    {
        // TODO Auto-generated method stub
        try
        {
            if (Security.getProvider("BC") == null)
            {
                BouncyCastleProvider bcp = new BouncyCastleProvider();
                Security.addProvider(bcp);
            }

            FileInputStream fis = new FileInputStream(new File("/tmp/token"));
            TimeStampResponse tr = new TimeStampResponse(fis);
            fis.close();
            // System.out.println("TimeStampResponse: " + tr);

            InputStream inStream = new FileInputStream("/tmp/tsa1_accv_ldap.cer");
            // "/home/paul/doc/java/workspace/ujiCrypto/etc/cagva.pem");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            inStream.close();

            tr.getTimeStampToken().validate(cert, "BC");
            HexDump h = new HexDump();

            TimeStampTokenInfo tstInfo = tr.getTimeStampToken().getTimeStampInfo();

            // TODO: Ojo, para acabar de validar el timestamp, deberíamos comparar este digest
            // con el digest obtenido de resumir los datos sobre los que hemos solicitado
            // el timestamp.
            System.out.println("Signed Digest: " + h.xdump(tstInfo.getMessageImprintDigest()));

        }
        catch (Exception e)
        {

            e.printStackTrace();

        }
    }

}
