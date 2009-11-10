package es.uji.security.crypto.pdf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;

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
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.config.ConfigManager;
import es.uji.security.util.OS;
import es.uji.security.util.i18n.LabelManager;

public class PDFSignatureFactory implements ISignFormatProvider
{
    private PrivateKey pk;
    private Provider pv;
    private Certificate[] chain;

    private ConfigManager conf = ConfigManager.getInstance();

    protected byte[] genPKCS7Signature(InputStream data, String tsaUrl, PrivateKey pk, Provider pv,
            Certificate[] chain) throws Exception
    {

        PdfPKCS7TSA sgn = new PdfPKCS7TSA(pk, chain, null, "SHA1", pv.getName(), true);

        byte[] buff = new byte[2048];
        int len = 0;

        while ((len = data.read(buff)) > 0)
        {
            sgn.update(buff, 0, len);
        }
        
        return sgn.getEncodedPKCS7(null, null, tsaUrl, null);

    }

    private void signPdf(PdfSignatureAppearance sap)
    {
        sap.setProvider(pv.getName());
        sap.setCrypto(pk, chain, null, PdfSignatureAppearance.WINCER_SIGNED);
        sap.setReason(conf.getProperty("PDFSIG_REASON"));
        sap.setLocation(conf.getProperty("PDFSIG_LOCATION"));
        sap.setContact(conf.getProperty("PDFSIG_CONTACT"));
    }
    
    // Take a look at http://itextpdf.sourceforge.net/howtosign.html#signtsocspjava
    private void signPdfTsp(PdfSignatureAppearance sap) throws Exception
    {
        PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKMS, PdfName.ADBE_PKCS7_SHA1);
    	
    	dic.setReason(conf.getProperty("PDFSIG_REASON"));
        dic.setLocation(conf.getProperty("PDFSIG_LOCATION"));
        dic.setContact(conf.getProperty("PDFSIG_CONTACT"));
        dic.setDate(new PdfDate(sap.getSignDate())); // time-stamp will over-rule this
        sap.setCryptoDictionary(dic);
        
        sap.setCrypto((PrivateKey) pk, chain, null, null);
        
        int contentEst = 15000;
        HashMap exc = new HashMap();
        exc.put(PdfName.CONTENTS, new Integer(contentEst * 2 + 2));
        sap.preClose(exc);
        
        // Get the true data signature, including a true time stamp token
        byte[] encodedSig = genPKCS7Signature(sap.getRangeStream(), conf.getProperty("PDFSIG_TSA_URL"), pk, pv, chain);

        if (contentEst + 2 < encodedSig.length)
        {
            throw new Exception("Timestamp size estimate " + contentEst + " is too low for actual "
                    + encodedSig.length);
        }

        // Copy signature into a zero-filled array, padding it up to estimate
        byte[] paddedSig = new byte[contentEst];

        System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);

        // Finally, load zero-padded signature into the signature field /Content
        PdfDictionary dic2 = new PdfDictionary();
        dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));

        sap.close(dic2);
    }

    private void createVisibleSignature(PdfSignatureAppearance sap) throws BadElementException,
            MalformedURLException, IOException
    {
        sap.setVisibleSignature(new Rectangle(Float.parseFloat(conf
                .getProperty("PDFSIG_VISIBLE_AREA_X")), Float.parseFloat(conf
                .getProperty("PDFSIG_VISIBLE_AREA_Y")), Float.parseFloat(conf
                .getProperty("PDFSIG_VISIBLE_AREA_X2")), Float.parseFloat(conf
                .getProperty("PDFSIG_VISIBLE_AREA_Y2"))), Integer.parseInt(conf
                .getProperty("PDFSIG_VISIBLE_AREA_PAGE")), null);
        sap.setAcro6Layers(true);

        byte[] imageData = OS.inputStreamToByteArray(PDFSignatureFactory.class.getClassLoader()
                .getResourceAsStream(conf.getProperty("PDFSIG_VISIBLE_AREA_IMGFILE")));
        Image image = Image.getInstance(imageData);

        sap.setSignatureGraphic(image);
        sap.setRender(PdfSignatureAppearance.SignatureRenderGraphicAndDescription);
    }

    public SignatureResult formatSignature(SignatureOptions signatureOptions)
            throws KeyStoreException, Exception
    {
        try
        {
            byte[] datos = OS.inputStreamToByteArray(signatureOptions.getDataToSign());
            X509Certificate sCer = signatureOptions.getCertificate();
            this.pk = signatureOptions.getPrivateKey();
            this.pv = signatureOptions.getProvider();

            if (Security.getProvider(this.pv.getName()) == null && this.pv != null)
            {
                Security.addProvider(this.pv);
            }

            chain = new Certificate[2];
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            // Here the certificates has to be disposed as next:
            // chain[0]= user_cert, chain[1]= level_n_cert,
            // chain[2]= level_n-1_cert, ...
            ClassLoader cl = PDFSignatureFactory.class.getClassLoader();

            SignatureResult signatureResult = new SignatureResult();

            // Get the CA certificate list
            Integer n = new Integer(conf.getProperty("PDFSIG_CA_CERTS"));
            Certificate cert = sCer;
            Certificate CACert = null;

            for (int i = 1; i <= n; i++)
            {
                CACert = cf.generateCertificate(cl.getResourceAsStream(conf
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
                signatureResult.setValid(false);
                signatureResult.addError(LabelManager.get("ERROR_CERTIFICATE_NOT_ALLOWED"));

                return signatureResult;
            }

            chain[1] = CACert;
            chain[0] = cert;

            /* Begin with the signature itself */
            PdfReader reader = new PdfReader(datos);
            ByteArrayOutputStream sout = new ByteArrayOutputStream();

            PdfStamper stp = PdfStamper.createSignature(reader, sout, '\0', null, true);

            PdfSignatureAppearance sap = stp.getSignatureAppearance();

            String aux = conf.getProperty("PDFSIG_VISIBLE_SIGNATURE");

            if (aux != null && aux.trim().equals("true"))
            {
                createVisibleSignature(sap);
            }

            aux = conf.getProperty("PDFSIG_TIMESTAMPING");
            if (aux != null && aux.trim().equals("true")
                    && conf.getProperty("PDFSIG_TSA_URL") != null)
            {
                signPdfTsp(sap);
            }
            else
            {
                signPdf(sap);
                stp.close();
            }

            signatureResult.setValid(true);
            signatureResult.setSignatureData(new ByteArrayInputStream(sout.toByteArray()));

            return signatureResult;
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return null;
    }
}
