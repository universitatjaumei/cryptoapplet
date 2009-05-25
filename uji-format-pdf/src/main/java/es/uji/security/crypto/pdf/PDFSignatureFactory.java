package es.uji.security.crypto.pdf;

import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;

import java.util.HashMap;
import java.util.Properties;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;


import java.lang.ClassLoader;
import java.net.MalformedURLException;

import com.lowagie.text.BadElementException;
import com.lowagie.text.Image;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.PdfDate;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignature;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.pdf.PdfString;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.cms.pdf.PdfPKCS7TSA;
import es.uji.security.crypto.cms.pdf.TSAClient;
import es.uji.security.crypto.cms.pdf.TSAClientBouncyCastle;
import es.uji.security.util.ConfigHandler;
import es.uji.security.util.i18n.LabelManager;

public class PDFSignatureFactory implements ISignFormatProvider
{
    private String _strerr = "";
    private Properties prop;
    private PrivateKey pk;
    private Provider pv;
    private Certificate[] chain;

	public static byte[] inputStreamToByteArray(InputStream in) throws IOException
	{
		byte[] buffer = new byte[2048];
	    int length = 0;

	    ByteArrayOutputStream baos = new ByteArrayOutputStream();

	    while ((length = in.read(buffer)) >= 0)
	    {
	    	baos.write(buffer, 0, length);
	    }

	    return baos.toByteArray();
	}

	protected byte[] genPKCS7Signature(InputStream data, TSAClient tsc, PrivateKey pk, Provider pv,
            Certificate[] chain) throws Exception
    {

        PdfPKCS7TSA sgn = new PdfPKCS7TSA(pk, chain, null, "SHA1", pv.getName(), true);

        byte[] buff = new byte[2048];
        int len = 0;

        while ((len = data.read(buff)) > 0)
        {
            sgn.update(buff, 0, len);
        }

        return sgn.getEncodedPKCS7(null, null, tsc);

    }

    private void signPdf(PdfSignatureAppearance sap)
    {
        sap.setProvider(pv.getName());
        sap.setCrypto(pk, chain, null, PdfSignatureAppearance.WINCER_SIGNED);
        sap.setReason(prop.getProperty("PDFSIG_REASON"));
        sap.setLocation(prop.getProperty("PDFSIG_REASON"));
        sap.setContact(prop.getProperty("PDFSIG_CONTACT"));
    }

    private void signPdfTsp(PdfSignatureAppearance sap) throws Exception
    {
        PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKMS, PdfName.ADBE_PKCS7_SHA1);
        dic.setReason(prop.getProperty("PDFSIG_REASON"));
        dic.setLocation(prop.getProperty("PDFSIG_LOCATION"));
        dic.setContact(prop.getProperty("PDFSIG_CONTACT"));
        dic.setDate(new PdfDate(sap.getSignDate())); // time-stamp will over-rule this
        sap.setCryptoDictionary(dic);
        sap.setCrypto((PrivateKey) pk, chain, null, null);

        // Estimate signature size, creating a 'fake' one using fake data (SHA1 length does not depend upon the data length)
        TSAClient tsc = new TSAClientBouncyCastle(prop.getProperty("PDFSIG_TSA_URL"), prop
                .getProperty("PDFSIG_TSA_ACCOUNT"), prop.getProperty("PDFSIG_TSA_PWD"));

        byte[] estSignature = genPKCS7Signature(new ByteArrayInputStream("fake".getBytes()), null,
                pk, pv, chain);
        int contentEst = estSignature.length + ((tsc == null) ? 0 : tsc.getTokenSizeEstimate());

        // Preallocate excluded byte-range for the signature content (hex encoded)
        HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
        exc.put(PdfName.CONTENTS, new Integer(contentEst * 2 + 2));
        sap.preClose(exc);

        // Get the true data signature, including a true time stamp token
        byte[] encodedSig = genPKCS7Signature(sap.getRangeStream(), tsc, pk, pv, chain);

        if (contentEst + 2 < encodedSig.length)
        {
            throw new Exception("Timestamp size estimate " + contentEst +
            " is too low for actual " +
            encodedSig.length);
        }

        // Copy signature into a zero-filled array, padding it up to estimate

        byte[] paddedSig = new byte[contentEst];

        System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);

        // Finally, load zero-padded signature into the signature field /Content
        PdfDictionary dic2 = new PdfDictionary();
        dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));

        sap.close(dic2);
    }
    
    private void createVisibleSignature(PdfSignatureAppearance sap) throws BadElementException, MalformedURLException, IOException
    {
        sap.setVisibleSignature(new Rectangle(
        	Float.parseFloat(prop.getProperty("PDFSIG_VISIBLE_AREA_X")), 
        	Float.parseFloat(prop.getProperty("PDFSIG_VISIBLE_AREA_Y")),
        	Float.parseFloat(prop.getProperty("PDFSIG_VISIBLE_AREA_X2")),
        	Float.parseFloat(prop.getProperty("PDFSIG_VISIBLE_AREA_Y2"))), 
        	Integer.parseInt(prop.getProperty("PDFSIG_VISIBLE_AREA_PAGE")), 
        	null);
        sap.setAcro6Layers(true);
        
        byte[] imageData = inputStreamToByteArray(PDFSignatureFactory.class.getClassLoader().getResourceAsStream(prop.getProperty("PDFSIG_VISIBLE_AREA_IMGFILE")));
        Image image = Image.getInstance(imageData);
        
        sap.setSignatureGraphic(image);
        sap.setRender(PdfSignatureAppearance.SignatureRenderGraphicAndDescription);
    }

    public byte[] formatSignature(SignatureOptions sigOpt) throws KeyStoreException, Exception
    {
        try
        {
            byte[] datos = sigOpt.getToSignByteArray();
            X509Certificate sCer = sigOpt.getCertificate();
            this.pk = sigOpt.getPrivateKey();
            this.pv = sigOpt.getProvider();

            if (Security.getProvider(this.pv.getName()) == null)
            {
                Security.addProvider(this.pv);
            }
            
            chain = new Certificate[2];
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            // Here the certificates has to be disposed as next:
            // chain[0]= user_cert, chain[1]= level_n_cert,
            // chain[2]= level_n-1_cert, ...
            ClassLoader cl = PDFSignatureFactory.class.getClassLoader();

            prop = ConfigHandler.getProperties();
            if (prop == null)
            {
                _strerr = LabelManager.get("ERROR_DDOC_NOCONFIGFILE");
                return null;
            }

            // Get the CA certificate list
            Integer n = new Integer(prop.getProperty("PDFSIG_CA_CERTS"));
            Certificate cert = sCer;
            Certificate CACert = null;

            for (int i = 1; i <= n; i++)
            {
                CACert = cf.generateCertificate(cl.getResourceAsStream(prop
                        .getProperty("PDFSIG_CA_CERT" + i)));
                try
                {
                    cert.verify(CACert.getPublicKey());
                    break;
                }
                catch (SignatureException e)
                {
                    // The actual CACert does not match with the
                    // signer certificate.
                    CACert = null;
                }
            }

            if (CACert == null)
            {
                _strerr = LabelManager.get("ERROR_CERTIFICATE_NOT_ALLOWED");
                return null;
            }

            chain[1] = CACert;
            chain[0] = cert;

            /* Begin with the signature itself */
            PdfReader reader = new PdfReader(datos);
            ByteArrayOutputStream sout = new ByteArrayOutputStream();

            PdfStamper stp = PdfStamper.createSignature(reader, sout, '\0');

            PdfSignatureAppearance sap = stp.getSignatureAppearance();

            String aux = prop.getProperty("PDFSIG_VISIBLE_SIGNATURE");
            
            if (aux != null && aux.trim().equals("true")) 
            {
            	createVisibleSignature(sap);
            }
            	
            aux = prop.getProperty("PDFSIG_TIMESTAMPING");
            if (aux != null && aux.trim().equals("true") && prop.getProperty("PDFSIG_TSA_URL") != null)
            {
                signPdfTsp(sap);
            }
            else
            {
                signPdf(sap);
                stp.close();
            }
            
            return sout.toByteArray();
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return null;
    }

    public String getError()
    {
        return _strerr;
    }
}
