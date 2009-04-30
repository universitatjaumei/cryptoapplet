package es.uji.security.crypto.cms;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.*;
import java.security.MessageDigest;
import java.security.interfaces.*;
import java.security.Signature;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Collection;
import java.util.Iterator;
import java.util.Set;
import java.util.HashSet;
import java.util.Vector;

import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.*;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.asn1.cms.AttributeTable;

public class CMSSignatureVerifier
{

    private X509Certificate[] _IntCert = null;
    private X509Certificate _Scert = null;
    private String _SubjectDN = null;
    private InputStream _stream = null;
    private InputStream _pkcs7Stream = null;
    private byte[] _signature = null;
    private RSAPublicKey _pk = null;

    CMSSignatureVerifier(String[] certs, InputStream stream, InputStream pkcs7Stream)
    {
        loadCerts(certs);
        _stream = stream;
        _pkcs7Stream = pkcs7Stream;
    }

    private void loadCerts(String[] intCertFiles)
    {
        try
        {
            _IntCert = new X509Certificate[intCertFiles.length];
            for (int i = 0; i < intCertFiles.length; i++)
            {
                InputStream inStream = new FileInputStream(intCertFiles[i]);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                _IntCert[i] = (X509Certificate) cf.generateCertificate(inStream);
                inStream.close();
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

    }

    public static void hexPrint(byte[] bytes)
    {
        try
        {
            Hex.encode(bytes, 0, bytes.length, System.out);
            System.out.println("");
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    // Inicializa proveedor de funcionalidades criptográficas BouncyCastle.
    private void providerInit()
    {
        if (Security.getProvider("BC") == null)
        {
            BouncyCastleProvider bcp = new BouncyCastleProvider();
            Security.insertProviderAt(bcp, 2);
        }
    }

    private boolean verifyAgainstCA(CertStore certs)
    {
        boolean result = false;

        try
        {
            List certChain = new ArrayList();
            X509Certificate rootCert = _IntCert[0];
            Collection certCollection = certs.getCertificates(null);
            certChain.add(rootCert);

            for (int i = 1; i < _IntCert.length; i++)
                certChain.add(_IntCert[i]);

            Iterator certIt = certCollection.iterator();

            for (int i = 0; i < certCollection.size(); i++)
            {
                certChain.add((X509Certificate) certIt.next());
            }

            CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(certChain);
            CertStore store = CertStore.getInstance("Collection", ccsp);
            CertPath cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certChain);

            Set<TrustAnchor> trust = new HashSet<TrustAnchor>();
            trust.add(new TrustAnchor(rootCert, null));

            PKIXParameters param = new PKIXParameters(trust);
            param.addCertStore(store);
            param.setRevocationEnabled(false);
            param.setTrustAnchors(trust);

            CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");

            try
            {
                cpv.validate(cp, param);
                result = true;
                System.out.println("Verificación de la cadena de certificación correcta.");
            }
            catch (CertPathValidatorException e)
            {
                result = false;
                e.printStackTrace();
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return result;
    }

    private byte[] readStream(InputStream stream)
    {
        byte[] bytes = null;
        try
        {
            InputStream is = stream;

            long length = stream.available();
            bytes = new byte[(int) length];

            int offset = 0;
            int numRead = 0;
            while (offset < bytes.length
                    && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0)
            {
                offset += numRead;
            }

            if (offset < bytes.length)
            {
                throw new IOException("No se ha podido leer el stream ");
            }
            is.close();
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return bytes;
    }

    public byte[] SHA1Digest()
    {
        byte[] digest = null;

        try
        {
            // Usaremos SHA-1
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");

            // Calculamos SHA-1
            messageDigest.update(readStream(_stream));

            digest = messageDigest.digest();
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return digest;
    }

    // Comprueba que la firma es correcta, que corresponde a los
    // datos en texto plano y que además, la cadena de certificación
    // ofrecida como primer argumento del constructor, valida la
    // .
    private boolean verifyCMS(CMSSignedData aSignedData) throws CMSException,
            NoSuchProviderException, NoSuchAlgorithmException, CertStoreException,
            CertificateNotYetValidException, CertificateExpiredException
    {

        providerInit();
        CertStore certs = aSignedData.getCertificatesAndCRLs("Collection", "BC");

        SignerInformationStore signers = aSignedData.getSignerInfos();
        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        boolean verificationResult = false;
        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation) it.next();
            SignerId signerId = signer.getSID();
            Collection certCollection = certs.getCertificates(signerId);

            Iterator certIt = certCollection.iterator();
            X509Certificate cert = (X509Certificate) certIt.next();
            _SubjectDN = cert.getSubjectDN().toString();
            _Scert = cert;
            verificationResult = signer.verify(cert, "BC");
            verifyAgainstCA(certs);
            _signature = signer.getSignature();
            _pk = (RSAPublicKey) cert.getPublicKey();

            AttributeTable signedAttrTable = signer.getSignedAttributes();

            Signature sig = Signature.getInstance("Sha1withRSAEncryption");
            try
            {
                sig.initVerify(_pk);
                sig.update(signer.getEncodedSignedAttributes());
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }
        return verificationResult;
    }

    private boolean verifyCAandSignature(byte[] aDataBytes, byte[] aSignature) throws CMSException,
            NoSuchProviderException, NoSuchAlgorithmException, CertStoreException,
            CertificateNotYetValidException, CertificateExpiredException
    {

        providerInit();

        CMSProcessableByteArray cmsByteArray = new CMSProcessableByteArray(aDataBytes);

        CMSSignedData cmsSd = new CMSSignedData(cmsByteArray, aSignature);

        return verifyCMS(cmsSd);
    }

    public boolean verifyPkcs7()
    {
        boolean result = false;

        try
        {

            // Load plain Text
            byte[] dataBytesPlainText = readStream(_stream);

            // Load and decode pkcs7 file
            byte[] _pkcs7Pem = readStream(_pkcs7Stream);
            byte[] derPkcs7 = Base64.decode(_pkcs7Pem);

            try
            {
                result = verifyCAandSignature(dataBytesPlainText, derPkcs7);
            }
            catch (CMSException e)
            {
                result = false;
                e.printStackTrace();
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return result;
    }

    public String getX509SubjectName()
    {
        return _SubjectDN;
    }

    public byte[] getSignature()
    {
        return _signature;
    }

    public RSAPublicKey getPublicKey()
    {
        return _pk;
    }

    public String getX509Certificate()
    {
        try
        {
            byte[] bytes = _Scert.getEncoded();
            String encoded = new String(Base64.encode(bytes));
            return encoded;
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * @param args
     */
    public static void main(String[] args)
    {

        Vector<String> caPaths = new Vector<String>();
        String cmsFile = null, dataFile = null;

        try
        {
            if (args.length == 0)
            {
                System.err
                        .println("Uso: CMSSignatureVerifier -ca0 root_ca -ca1 level2_ca -ca2 level3_ca ... -data data.txt -cms cms.pem");
                System.exit(-1);
            }
            int n_ca = 0;
            for (int i = 0; i < args.length; i++)
            {
                try
                {
                    if (args[i].startsWith("-ca"))
                    {
                        int aux = Integer.parseInt(args[i].substring(3));
                        if (aux != n_ca)
                        {
                            throw new Exception("CA args not in order");
                        }
                        caPaths.add(args[i + 1]);
                        n_ca++;
                    }
                    else if (args[i].equals("-data"))
                    {
                        dataFile = args[i + 1];
                    }
                    else if (args[i].equals("-cms"))
                    {
                        cmsFile = args[i + 1];
                    }
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                    System.err
                            .println("Uso: CMSSignatureVerifier -ca0 root_ca -ca1 level2_ca -ca2 level3_ca ... -data data.txt -cms cms.pem");
                    System.exit(-1);
                }
            }
            String[] x = new String[0];
            CMSSignatureVerifier pv = new CMSSignatureVerifier(caPaths.toArray(x),
                    new FileInputStream(dataFile), new FileInputStream(cmsFile));
            System.out.println("Resultado verificacion: " + pv.verifyPkcs7());
            System.out.print("SHA-1:");
            hexPrint(pv.SHA1Digest());
            System.out.println("DN del firmante: " + pv.getX509SubjectName());
            System.out.println("X509 User Cert: " + pv.getX509Certificate());
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

}
