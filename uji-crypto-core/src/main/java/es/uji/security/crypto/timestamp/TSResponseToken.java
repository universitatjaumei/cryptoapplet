package es.uji.security.crypto.timestamp;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;

import javax.crypto.Cipher;

import es.uji.security.util.asn1.DERObjectIdentifier;

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
            int j = 3;
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
            	j+=2;
            
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
            throw new ASN1ParseException("The ASN.1 structure is not well formed, the length tag does not match with its real length.");
        }
    }

    public Date getUTCTime() throws IOException, ASN1ParseException
    {
        DateFormat dfm = new SimpleDateFormat("yyyyMMddHHmmss");
        dfm.setTimeZone(new SimpleTimeZone(0, "Z"));

        byte[] tok = response.getToken().getContentInfo().getContentBytes();

        try
        {
            int j = 3;
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
            throw new ASN1ParseException("The ASN.1 structure is not well formed, the length tag does not match with its real length.");
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
     * @throws ASN1ParseException 
     * @throws TokenVerifyException 
     * 
     * */

    public boolean verify(X509Certificate cert) throws IOException, TokenVerifyException, ASN1ParseException
    {
        return verify(cert, null, false, "SHA-1");
    }

    public boolean verify(X509Certificate cert, byte[] origData) throws IOException, TokenVerifyException, ASN1ParseException
    {
        return verify(cert, origData, true, "SHA-1");
    }

    public boolean verify(X509Certificate cert, byte[] origData, boolean verifyData,
            String signatureDigestAlgorithm) throws IOException, TokenVerifyException,
            ASN1ParseException
    {
        byte[] pk9enc = response.getToken().getSignerInfos()[0].getAuthenticatedAttributes()
                .getDerEncoding();
        byte[] ciphdig = response.getToken().getSignerInfos()[0].getEncryptedDigest();

        Cipher ciph = null;
        byte[] deciphdig = null;
        MessageDigest messageDigest = null;
        byte[] digest = null;
        
        try
        {
            ciph = Cipher.getInstance("RSA");
            ciph.init(Cipher.DECRYPT_MODE, cert);
            
            deciphdig = ciph.doFinal(ciphdig);

            messageDigest = MessageDigest.getInstance(signatureDigestAlgorithm);
            digest = messageDigest.digest(pk9enc);            
        }
        catch (Exception e)
        {
            throw new TokenVerifyException("Unable to decipher pkcs#9 encoded attributes");
        }

        // Parse asn1 deciphered structure:
        /*
         * 0 33: SEQUENCE { 2 9: SEQUENCE { 4 5: OBJECT IDENTIFIER sha1 (1 3 14 3 2 26) 11 0: NULL :
         * } 13 20: OCTET STRING : B2 89 51 1E 57 C3 ED B9 2A EF 91 86 DE E8 FA A7 : C4 9D EE 3A : }
         */
        // 4 bytes two sequences
        int i = 4;
        if (deciphdig[i] != 0x06)
        { // OID
            throw new ASN1ParseException("Must be an OID at position " + i);
        }
        String oid = DERObjectIdentifier.getOIDasString(deciphdig, i + 2, deciphdig[i + 1]);
        String hashAlg = DERObjectIdentifier.getHashAlgorithFromOID(oid);

        if (!hashAlg.equals("SHA1") && !hashAlg.equals("SHA256") && !hashAlg.equals("SHA384")
                && !hashAlg.equals("SHA512"))
        {
            // Invalid algorithm (not supported)
            throw new ASN1ParseException("Signature hash algorithm not supported");
        }
        i += deciphdig[i + 1] + 2;

        if (deciphdig[i] != 0x04)
        {
            // Could be a NULL tag
            i += deciphdig[i + 1] + 2;
            // Now we must point to the hash
            if (deciphdig[i] != 0x04)
            {
                throw new ASN1ParseException("Must be a hash value at position " + i);
            }
        }

        // The length must be the same:
        if (digest.length != deciphdig[i + 1])
        {
            throw new ASN1ParseException("The lenght between the plain and signed hash does not match!");
        }
        i += 2;

        // We are pointing at the hash now, so we can compare it:
        for (int j = 0; j < digest.length; j++)
        {
            if (digest[j] != deciphdig[i + j])
            {
                throw new TokenVerifyException("Plain and signed hash are different!");
            }
        }

        // Here we have checked the signature is correct.
        // Now check the message imprint.
        if (verifyData)
        {
            messageDigest.reset();
            byte[] oddig = messageDigest.digest(origData);
            byte[] msgImp = getMessageImprint();
            if (oddig.length != msgImp.length)
            {
                throw new TokenVerifyException("The lenght between the calculated and signed hash does not match!");
            }

            for (int j = 0; j < oddig.length; j++)
            {
                if (oddig[j] != msgImp[j])
                {
                    throw new TokenVerifyException("Plain and signed hash are different!");
                }
            }
        }

        return true;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException,
            IOException
    {        
        try
        {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

            // get user password and file input stream
            char[] password = "cryptoapplet".toCharArray();
            FileInputStream fis = new FileInputStream("../uji.keystore");
            ks.load(fis, password);
            fis.close();

            X509Certificate cert = (X509Certificate) ks.getCertificate("TSA1_ACCV");
            
            // Works fine
            TSResponse r = TimeStampFactory.getTimeStampResponse("http://tss.accv.es:8318/tsa",
                    "test".getBytes(), true);
            
            FileOutputStream fos = new FileOutputStream("/tmp/out1.bin");
            fos.write(r.getEncodedToken());
            fos.flush();
            fos.close();
            
            // Fails
            byte[] data = TimeStampFactory.getTimeStamp("http://tss.accv.es:8318/tsa",
                    "test".getBytes(), true);    
            fos = new FileOutputStream("/tmp/out2.bin");
            fos.write(data);
            fos.flush();
            fos.close();
            
            r = new TSResponse(data);

            TSResponseToken tsResponseToken = new TSResponseToken(r);

            System.out.print("Successful verification: ");
            System.out.println(" " + tsResponseToken.verify(cert, "test".getBytes()));

            System.out.print("Bad data digest verification: ");
            System.out.println(" " + tsResponseToken.verify(cert, "testx".getBytes()));

            System.out.print("No original data check verification: ");
            System.out.println(" " + tsResponseToken.verify(cert, null, false, "SHA-1"));
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}
