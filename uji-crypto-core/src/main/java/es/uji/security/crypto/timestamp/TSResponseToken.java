package es.uji.security.crypto.timestamp;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;

import javax.crypto.Cipher;

import es.uji.security.util.asn1.DERObjectIdentifier;
import sun.security.x509.AlgorithmId;

public class TSResponseToken
{
    private TSResponse response;

    public TSResponseToken(TSResponse response)
    {
        this.response = response;

    }

    public byte[] getMessageImprint() throws IOException, ASN1ParseException
    {
        byte[] tok = response.getToken().getContentInfo().getContentBytes();

        try
        {
            int j = 0;
            
            while (tok[j] != 0x02 && j < tok.length)
            {
                j++;
            }
            
            // Tok is the der encoded array
            // First a 30 81 TAM sequence and tam is indicated so
            // at position i=3 we must find an integer 0x02

            if (tok[j] != 0x02)
                throw new ASN1ParseException("Must be an integer at position " + j);

            // Now we must get the length of the integer and skip it
            j += tok[j + 1] + 2;

            // An oid with the tsa policy must be found.
            if (tok[j] != 0x06)
                throw new ASN1ParseException("Must be an OID with the TSA policy at position " + j);

            // skip tsaPolicy OID length
            j += tok[j + 1] + 2;

            // Now four bytes of a double sequence:
            j += 4;

            // And now we point to the hash algorith oid.
            if (tok[j] != 0x06)
                throw new ASN1ParseException("Must be a hash algorith oid at position " + j);

            // skip hashalg OID length
            j += tok[j + 1] + 2;

            // We can find a NULL value here:
            if (tok[j] == 0x05)
                j += 2;

            // And now we point to the hash itself.
            if (tok[j] != 0x04)
                throw new ASN1ParseException("Must be a hash value at position " + j);

            int l = tok[j + 1];
            byte[] hash = new byte[l];
            System.arraycopy(tok, j + 2, hash, 0, l);
            return hash;
        }
        catch (ArrayIndexOutOfBoundsException ai)
        {
            // Parsing failure, null will be returned.
            throw new ASN1ParseException(
                    "The ASN.1 structure is not well formed, the length tag does not match with its real length.");
        }
    }

    public Date getUTCTime() throws IOException, ASN1ParseException
    {
        DateFormat dfm = new SimpleDateFormat("yyyyMMddHHmmss");
        dfm.setTimeZone(new SimpleTimeZone(0, "Z"));

        byte[] tok = response.getToken().getContentInfo().getContentBytes();

        try
        {
            int j = 0;
            
            while (tok[j] != 0x02 && j < tok.length)
            {
                j++;
            }

            // Tok is the der encoded array
            // First a 30 81 TAM sequence and tam is indicated so
            // at position i=3 we must find an integer 0x02

            if (tok[j] != 0x02)
                throw new ASN1ParseException("Must be an integer at position " + j);

            // Now we must get the length of the integer and skip it
            j += tok[j + 1] + 2;

            // An oid with the tsa policy must be found.
            if (tok[j] != 0x06)
                throw new ASN1ParseException("Must be a tsa policy at position " + j);

            // skip tsaPolicy OID length
            j += tok[j + 1] + 2;

            // Now four bytes of a double sequence:
            j += 4;

            // And now we point to the hash algorithm oid.
            if (tok[j] != 0x06)
                throw new ASN1ParseException("Must be a hash algorithm oid at position " + j);

            // skip hashalg OID length
            j += tok[j + 1] + 2;

            // We can find a NULL value here:
            if (tok[j] == 0x05)
                j += 2;
            
            // And now we point to the hash itself.
            if (tok[j] != 0x04)
                throw new ASN1ParseException("Must be a hash value at position " + j);

            // skip hash length and serial integer
            j += tok[j + 1] + 2;
            j += tok[j + 1] + 2;

            // And now we point to the time.
            if (tok[j] != 0x18)
                throw new ASN1ParseException("Must be a time value at position " + j);

            // The UTC generalized time.
            String genTime = new String(tok, j + 2, tok[j + 1]);
            return dfm.parse(genTime);
        }
        catch (ArrayIndexOutOfBoundsException ai)
        {
            // Parsing failure, null will be returned
            throw new ASN1ParseException(
                    "The ASN.1 structure is not well formed, the length tag does not match with its real length.");
        }
        catch (ParseException pe)
        {
            // Parsing failure, null will be returned
            throw new ASN1ParseException("Unable to parse the time as yyyyMMddHHmmss");
        }
    }

    /**
     * 
     * Verify the timeStamp token, this function is not enought verification, the certificate passed
     * here must be checked against the ca trust anchor.
     * 
     * @throws ASN1ParseException
     * @throws TokenVerifyException
     * 
     * */

    public boolean verify(X509Certificate cert) throws IOException, TokenVerifyException,
            ASN1ParseException
    {
        return verify(cert, null, false);
    }

    public boolean verify(X509Certificate cert, byte[] origData) throws IOException,
            TokenVerifyException, ASN1ParseException
    {
        return verify(cert, origData, true);
    }

    public boolean verify(X509Certificate cert, byte[] origData, boolean verifyData)
            throws IOException, TokenVerifyException, ASN1ParseException
    {
        byte[] pk9enc = response.getToken().getSignerInfos()[0].getAuthenticatedAttributes()
                .getDerEncoding();
        byte[] ciphdig = response.getToken().getSignerInfos()[0].getEncryptedDigest();

        byte[] deciphdig = null;
        MessageDigest messageDigest = null;
        byte[] digest = null;

        try
        {
            // Determine the message digest algorithm
            String messageDigestAlgorithm = "SHA-1";
            AlgorithmId[] digestAlgorithmIds = this.response.getToken().getDigestAlgorithmIds();

            if (digestAlgorithmIds != null && digestAlgorithmIds.length > 0) {
                messageDigestAlgorithm = digestAlgorithmIds[0].getName();
            }

            // Map digest algorithm to signature algorithm
            String signatureAlgorithm;
            if (messageDigestAlgorithm.equals("SHA-256") || messageDigestAlgorithm.equals("SHA256")) {
                signatureAlgorithm = "SHA256withRSA";
            } else if (messageDigestAlgorithm.equals("SHA-384") || messageDigestAlgorithm.equals("SHA384")) {
                signatureAlgorithm = "SHA384withRSA";
            } else if (messageDigestAlgorithm.equals("SHA-512") || messageDigestAlgorithm.equals("SHA512")) {
                signatureAlgorithm = "SHA512withRSA";
            } else {
                signatureAlgorithm = "SHA1withRSA";
            }

            // Verify signature using proper Signature API
            Signature sig = Signature.getInstance(signatureAlgorithm);
            sig.initVerify(cert.getPublicKey());
            sig.update(pk9enc);

            if (!sig.verify(ciphdig)) {
                throw new TokenVerifyException("Signature verification failed");
            }

            // Signature is valid. Now check the message imprint if requested.
            if (verifyData && origData != null)
            {
                messageDigest = MessageDigest.getInstance(messageDigestAlgorithm);
                byte[] oddig = messageDigest.digest(origData);
                byte[] msgImp = getMessageImprint();
                if (oddig.length != msgImp.length)
                {
                    throw new TokenVerifyException(
                            "The length between the calculated and signed hash does not match!");
                }

                for (int j = 0; j < oddig.length; j++)
                {
                    if (oddig[j] != msgImp[j])
                    {
                        throw new TokenVerifyException("Calculated and message imprint hashes are different!");
                    }
                }
            }

            // Signature verified successfully
            return true;
        }
        catch (TokenVerifyException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            e.printStackTrace();
            throw new TokenVerifyException("Unable to verify timestamp signature: " + e.getMessage(), e);
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException,
            IOException, CertificateException, KeyStoreException, TokenVerifyException, ASN1ParseException
    {
        String tsaURL = "http://tss.accv.es:8318/tsa";
        
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

        // get user password and file input stream
        char[] password = "cryptoapplet".toCharArray();
        FileInputStream fis = new FileInputStream("/opt/devel/workspaces/cryptoapplet-github/uji.keystore");
        ks.load(fis, password);
        fis.close();

        X509Certificate cert = (X509Certificate) ks.getCertificate("TSA1_ACCV");
        
        TSResponse r = TimeStampFactory.getTimeStampResponse(tsaURL, "test"
                .getBytes(), true, "SHA-256");

        TSResponseToken tsResponseToken = new TSResponseToken(r);

        System.out.print("Successful verification: ");
        System.out.println(" " + tsResponseToken.verify(cert, "test".getBytes()));

        System.out.print("Bad data digest verification: ");

        try
        {
            System.out.println(" " + tsResponseToken.verify(cert, "testx".getBytes()));
        }
        catch (Exception e)
        {
            System.out.println(e.getLocalizedMessage());
        }

        System.out.print("No original data check verification: ");
        System.out.println(" " + tsResponseToken.verify(cert, null, false));
    }
}