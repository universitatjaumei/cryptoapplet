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
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import com.lowagie.text.DocumentException;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.Image;
import com.lowagie.text.Phrase;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.ColumnText;
import com.lowagie.text.pdf.PdfDate;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignature;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.pdf.PdfString;
import com.lowagie.text.pdf.PdfTemplate;
import com.lowagie.text.pdf.PdfWriter;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.config.CertificateUtils;
import es.uji.security.crypto.config.ConfigManager;
import es.uji.security.crypto.config.OS;
import es.uji.security.util.i18n.LabelManager;

public class PDFSignatureFactory implements ISignFormatProvider
{
    private static final int PADDING = 3;

    private PrivateKey privateKey;
    private Provider provider;
    private Certificate[] chain;
    private ConfigManager conf = ConfigManager.getInstance();

    private Font font;

    public PDFSignatureFactory()
    {
        initFontDefinition();
    }

    private void initFontDefinition()
    {
        String fontSizeProperty = conf.getProperty("PDFSIG_VISIBLE_AREA_TEXT_SIZE");
        int fontSize = 8;

        try
        {
            fontSize = Integer.parseInt(fontSizeProperty);
        }
        catch (Exception e)
        {
        }

        font = new Font();
        font.setSize(fontSize);
    }

    protected byte[] genPKCS7Signature(InputStream data, String tsaUrl, PrivateKey pk,
            Provider provider, Certificate[] chain) throws Exception
    {
        PdfPKCS7TSA sgn = new PdfPKCS7TSA(pk, chain, null, "SHA1", provider, true);

        byte[] buff = new byte[2048];
        int len = 0;

        while ((len = data.read(buff)) > 0)
        {
            sgn.update(buff, 0, len);
        }

        return sgn.getEncodedPKCS7(null, null, tsaUrl, null);
    }

    private void sign(PdfSignatureAppearance pdfSignatureAppearance) throws Exception
    {
        // Check if TSA support is enabled

        String timestamping = conf.getProperty("PDFSIG_TIMESTAMPING");
        String tsaUrl = conf.getProperty("PDFSIG_TSA_URL");

        boolean enableTSP = false;

        if (timestamping != null && timestamping.trim().equals("true") && tsaUrl != null)
        {
            enableTSP = true;
        }

        // Add configured values

        String reason = conf.getProperty("PDFSIG_REASON");
        String location = conf.getProperty("PDFSIG_LOCATION");
        String contact = conf.getProperty("PDFSIG_CONTACT");

        if (enableTSP)
        {
            PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKMS, PdfName.ADBE_PKCS7_SHA1);

            dic.setReason(reason);
            dic.setLocation(location);
            dic.setContact(contact);
            dic.setDate(new PdfDate(pdfSignatureAppearance.getSignDate())); // time-stamp will
            // over-rule this

            pdfSignatureAppearance.setCryptoDictionary(dic);
            pdfSignatureAppearance.setCrypto((PrivateKey) privateKey, chain, null, null);

            int contentEst = 15000;

            HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
            exc.put(PdfName.CONTENTS, new Integer(contentEst * 2 + 2));
            pdfSignatureAppearance.preClose(exc);

            // Get the true data signature, including a true time stamp token

            byte[] encodedSig = genPKCS7Signature(pdfSignatureAppearance.getRangeStream(), tsaUrl,
                    privateKey, provider, chain);

            if (contentEst + 2 < encodedSig.length)
            {
                throw new Exception("Timestamp size estimate " + contentEst
                        + " is too low for actual " + encodedSig.length);
            }

            // Copy signature into a zero-filled array, padding it up to estimate
            byte[] paddedSig = new byte[contentEst];

            System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);

            // Finally, load zero-padded signature into the signature field /Content
            PdfDictionary dic2 = new PdfDictionary();
            dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
            pdfSignatureAppearance.close(dic2);
        }
        else
        {
            pdfSignatureAppearance.setProvider(provider.getName());
            pdfSignatureAppearance.setCrypto(privateKey, chain, null,
                    PdfSignatureAppearance.WINCER_SIGNED);
            pdfSignatureAppearance.setReason(reason);
            pdfSignatureAppearance.setLocation(location);
            pdfSignatureAppearance.setContact(contact);
        }
    }

    private void createVisibleSignature(PdfSignatureAppearance sap, int numSignatures,
            String pattern, Map<String, String> bindValues) throws MalformedURLException,
            IOException, DocumentException
    {
        float x1 = Float.parseFloat(conf.getProperty("PDFSIG_VISIBLE_AREA_X"));
        float y1 = Float.parseFloat(conf.getProperty("PDFSIG_VISIBLE_AREA_Y"));
        float x2 = Float.parseFloat(conf.getProperty("PDFSIG_VISIBLE_AREA_X2"));
        float y2 = Float.parseFloat(conf.getProperty("PDFSIG_VISIBLE_AREA_Y2"));

        float offset = (x2 - x1) * numSignatures;

        // Position of the visible signature

        Rectangle rectangle = new Rectangle(x1 + offset, y1, x2 + offset, y2);

        sap.setVisibleSignature(rectangle, Integer.parseInt(conf
                .getProperty("PDFSIG_VISIBLE_AREA_PAGE")), null);
        sap.setAcro6Layers(true);
        sap.setLayer2Font(font);

        // Compute pattern

        String signatureText = null;

        if (pattern != null && pattern.length() > 0)
        {
            PatternParser patternParser = new PatternParser(pattern);
            signatureText = patternParser.parse(bindValues);
        }

        // Determine the visible signature type

        String signatureType = conf.getProperty("PDFSIG_VISIBLE_SIGNATURE_TYPE",
                "GRAPHIC_AND_DESCRIPTION");

        if (signatureType.equals("GRAPHIC_AND_DESCRIPTION"))
        {
            updateLayerGraphiAndDescription(sap, rectangle, signatureText);
            sap.setRender(PdfSignatureAppearance.SignatureRenderGraphicAndDescription);
        }
        else if (signatureType.equals("DESCRIPTION"))
        {
            sap.setLayer2Text(signatureText);
            sap.setRender(PdfSignatureAppearance.SignatureRenderDescription);
        }
        else if (signatureType.equals("NAME_AND_DESCRIPTION"))
        {
            sap.setLayer2Text(signatureText);
            sap.setRender(PdfSignatureAppearance.SignatureRenderNameAndDescription);
        }
    }

    private void updateLayerGraphiAndDescription(PdfSignatureAppearance pdfSignatureAppearance,
            Rectangle rectangle, String signatureText) throws DocumentException, IOException
    {
        // Retrieve image

        byte[] imageData = OS.inputStreamToByteArray(PDFSignatureFactory.class.getClassLoader()
                .getResourceAsStream(conf.getProperty("PDFSIG_VISIBLE_AREA_IMGFILE")));
        Image image = Image.getInstance(imageData);

        if (signatureText != null)
        {
            // Retrieve and reset Layer2

            PdfTemplate pdfTemplate = pdfSignatureAppearance.getLayer(2);
            pdfTemplate.reset();

            float width = Math.abs(rectangle.getWidth());
            float height = Math.abs(rectangle.getHeight());

            pdfTemplate.addImage(image, height, 0, 0, height, PADDING, PADDING);

            // Add text

            ColumnText ct = new ColumnText(pdfTemplate);
            ct.setRunDirection(PdfWriter.RUN_DIRECTION_DEFAULT);
            ct.setSimpleColumn(new Phrase(signatureText, font), height + PADDING * 2, 0, width
                    - PADDING, height, font.getSize(), Element.ALIGN_LEFT);
            ct.go();
        }
        else
        {
            pdfSignatureAppearance.setSignatureGraphic(image);
        }
    }

    public SignatureResult formatSignature(SignatureOptions signatureOptions)
            throws KeyStoreException, Exception
    {
        try
        {
            byte[] datos = OS.inputStreamToByteArray(signatureOptions.getDataToSign());
            X509Certificate certificate = signatureOptions.getCertificate();
            this.privateKey = signatureOptions.getPrivateKey();
            this.provider = signatureOptions.getProvider();

            if (Security.getProvider(this.provider.getName()) == null && this.provider != null)
            {
                Security.addProvider(this.provider);
            }

            chain = new Certificate[2];

            // Here the certificates has to be disposed as next:
            // chain[0]= user_cert, chain[1]= level_n_cert,
            // chain[2]= level_n-1_cert, ...

            SignatureResult signatureResult = new SignatureResult();

            // Get the CA certificate list
            Integer n = new Integer(conf.getProperty("DIGIDOC_CA_CERTS"));
            Certificate cert = certificate;
            Certificate CACert = null;

            for (int i = 1; i <= n; i++)
            {
                CACert = ConfigManager.readCertificate(conf.getProperty("DIGIDOC_CA_CERT" + i));

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

            // Begin with the signature itself

            PdfReader reader = new PdfReader(datos);
            ByteArrayOutputStream sout = new ByteArrayOutputStream();

            PdfStamper pdfStamper = PdfStamper.createSignature(reader, sout, '\0', null, true);
            PdfSignatureAppearance pdfSignatureAppareance = pdfStamper.getSignatureAppearance();

            String visibleSignature = conf.getProperty("PDFSIG_VISIBLE_SIGNATURE");
            boolean isVisibleSignature = (visibleSignature != null && visibleSignature.trim()
                    .equals("true"));

            if (isVisibleSignature)
            {
                String pattern = conf.getProperty("PDFSIG_VISIBLE_AREA_TEXT_PATTERN");

                Map<String, String> bindValues = signatureOptions
                        .getVisibleSignatureTextBindValues();

                if (bindValues != null)
                {
                    bindValues.put("%s", CertificateUtils.getCn(certificate));
                    
                    SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
                    bindValues.put("%t", simpleDateFormat.format(new Date()));
                }

                int numSignatures = reader.getAcroFields().getSignatureNames().size();

                createVisibleSignature(pdfSignatureAppareance, numSignatures, pattern, bindValues);
            }

            sign(pdfSignatureAppareance);

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
