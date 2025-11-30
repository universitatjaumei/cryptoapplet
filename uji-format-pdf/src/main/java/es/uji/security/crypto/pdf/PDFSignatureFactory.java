package es.uji.security.crypto.pdf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.util.encoders.Hex;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Element;
import com.itextpdf.text.Font;
import com.itextpdf.text.Image;
import com.itextpdf.text.Phrase;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.BaseFont;
import com.itextpdf.text.pdf.ColumnText;
import com.itextpdf.text.pdf.PdfAnnotation;
import com.itextpdf.text.pdf.PdfContentByte;
import com.itextpdf.text.pdf.PdfDate;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfFormField;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignature;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.PdfTemplate;
import com.itextpdf.text.pdf.PdfWriter;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.config.ConfigManager;
import es.uji.security.crypto.config.OS;
import es.uji.security.util.i18n.LabelManager;

public class PDFSignatureFactory implements ISignFormatProvider
{
    private Logger log = Logger.getLogger(PDFSignatureFactory.class);

    private static final int PADDING = 3;

    private PrivateKey privateKey;
    private Provider provider;
    private ConfigManager conf = ConfigManager.getInstance();
    private ConfigurationAdapter confAdapter;

    private Font font;

    private void initFontDefinition()
    {
        log.debug("VisibleAreaTextSize: " + confAdapter.getVisibleAreaTextSize());

        font = new Font();
        font.setSize(confAdapter.getVisibleAreaTextSize());
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

    private void sign(PdfStamper pdfStamper, PdfSignatureAppearance pdfSignatureAppearance, Certificate[] chain)
            throws Exception
    {
        // Check if TSA support is enabled

        boolean enableTSP = false;

        if (confAdapter.isTimestamping() && confAdapter.getTsaURL() != null)
        {
            enableTSP = true;
        }

        // Add configured values

        if (enableTSP)
        {
            PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKMS, PdfName.ADBE_PKCS7_SHA1);

            dic.setReason(confAdapter.getReason());
            dic.setLocation(confAdapter.getLocation());
            dic.setContact(confAdapter.getContact());
            dic.setDate(new PdfDate(pdfSignatureAppearance.getSignDate())); // time-stamp will
            // over-rule this

            pdfSignatureAppearance.setCryptoDictionary(dic);
            // In iText 5, setCrypto with this signature was removed
            // The signature dictionary is set directly with setCryptoDictionary

            int contentEst = 15000;

            HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
            exc.put(PdfName.CONTENTS, new Integer(contentEst * 2 + 2));
            pdfSignatureAppearance.preClose(exc);

            // Get the true data signature, including a true time stamp token

            byte[] encodedSig = genPKCS7Signature(pdfSignatureAppearance.getRangeStream(),
                    confAdapter.getTsaURL(), privateKey, provider, chain);

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
            // In iText 5, setProvider and setCrypto with WINCER_SIGNED were removed
            // Use the modern signature approach
            pdfSignatureAppearance.setCertificate(chain[0]);
            pdfSignatureAppearance.setReason(confAdapter.getReason());
            pdfSignatureAppearance.setLocation(confAdapter.getLocation());
            pdfSignatureAppearance.setContact(confAdapter.getContact());

            // Create the signature without timestamp
            PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
            dic.setReason(confAdapter.getReason());
            dic.setLocation(confAdapter.getLocation());
            dic.setContact(confAdapter.getContact());
            dic.setDate(new PdfDate(pdfSignatureAppearance.getSignDate()));
            pdfSignatureAppearance.setCryptoDictionary(dic);

            int contentEst = 8192;
            HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
            exc.put(PdfName.CONTENTS, new Integer(contentEst * 2 + 2));
            pdfSignatureAppearance.preClose(exc);

            byte[] encodedSig = genPKCS7Signature(pdfSignatureAppearance.getRangeStream(),
                    null, privateKey, provider, chain);

            byte[] paddedSig = new byte[contentEst];
            System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);

            PdfDictionary dic2 = new PdfDictionary();
            dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
            pdfSignatureAppearance.close(dic2);
        }
    }

    private void createVisibleSignature(PdfSignatureAppearance sap, int numSignatures,
                                        String pattern, Map<String, String> bindValues) throws MalformedURLException,
            IOException, DocumentException
    {
        float x1 = confAdapter.getVisibleAreaX();
        float y1 = confAdapter.getVisibleAreaY();
        float x2 = confAdapter.getVisibleAreaX2();
        float y2 = confAdapter.getVisibleAreaY2();

        float offsetX = ((x2 - x1) * numSignatures) + 10;
        float offsetY = ((y2 - y1) * numSignatures) + 10;

        log.debug("VisibleArea: " + x1 + "," + y1 + "," + x2 + "," + y2 + " offsetX:" + offsetX
                + ", offsetY:" + offsetY);

        // Position of the visible signature

        Rectangle rectangle = null;

        if (confAdapter.getVisibleAreaRepeatAxis().equals("Y"))
        {
            rectangle = new Rectangle(x1, y1 + offsetY, x2, y2 + offsetY);
        }
        else
        {
            rectangle = new Rectangle(x1 + offsetX, y1, x2 + offsetX, y2);
        }

        log.debug("VisibleAreaPage: " + confAdapter.getVisibleAreaPage());

        //sap.setVisibleSignature(rectangle, Integer.parseInt(confAdapter.getVisibleAreaPage()), null);
        sap.setVisibleSignature("CryptoAppletSignatureReference" + numSignatures);
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

        String signatureType = confAdapter.getVisibleSignatureType();
        log.debug("VisibleSignatureType: " + signatureType);

        if (signatureType.equals("GRAPHIC_AND_DESCRIPTION"))
        {
            updateLayerGraphiAndDescription(sap, rectangle, signatureText);
            sap.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION);
        }
        else if (signatureType.equals("DESCRIPTION"))
        {
            sap.setLayer2Text(signatureText);
            sap.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
        }
        else if (signatureType.equals("NAME_AND_DESCRIPTION"))
        {
            sap.setLayer2Text(signatureText);
            sap.setRenderingMode(PdfSignatureAppearance.RenderingMode.NAME_AND_DESCRIPTION);
        }
    }

    private void updateLayerGraphiAndDescription(PdfSignatureAppearance pdfSignatureAppearance,
                                                 Rectangle rectangle, String signatureText) throws DocumentException, IOException
    {
        // Retrieve image

        log.debug("VisibleAreaImgFile: " + confAdapter.getVisibleAreaImgFile());

        byte[] imageData = OS.inputStreamToByteArray(PDFSignatureFactory.class.getClassLoader()
                .getResourceAsStream(confAdapter.getVisibleAreaImgFile()));
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

    private Certificate findCACertificateFor(Certificate cert)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException
    {
        Integer n = new Integer(conf.getProperty("DIGIDOC_CA_CERTS"));
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

        return CACert;
    }

    public SignatureResult formatSignature(SignatureOptions signatureOptions) throws Exception
    {
        log.debug("Init PDF signature configuration");

        this.confAdapter = new ConfigurationAdapter(signatureOptions);

        initFontDefinition();

        byte[] datos = OS.inputStreamToByteArray(signatureOptions.getDataToSign());
        X509Certificate certificate = signatureOptions.getCertificate();
        this.privateKey = signatureOptions.getPrivateKey();
        this.provider = signatureOptions.getProvider();
        String reference = signatureOptions.getDocumentReference();
        String validationUrl = signatureOptions.getDocumentReferenceVerificationUrl();

        if (Security.getProvider(this.provider.getName()) == null && this.provider != null)
        {
            Security.addProvider(this.provider);
        }

        Certificate caCertificate = findCACertificateFor(certificate);

        if (certificate.getIssuerDN().equals(certificate.getSubjectDN())) {
            caCertificate = certificate;
        }
        else if (caCertificate == null)
        {
            SignatureResult signatureResult = new SignatureResult();
            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERROR_CERTIFICATE_NOT_ALLOWED"));

            return signatureResult;
        }

        PdfReader reader = new PdfReader(datos);
        ByteArrayOutputStream sout = new ByteArrayOutputStream();

        int numSignatures = reader.getAcroFields().getSignatureNames().size();

        if (numSignatures == 0 && reference != null)
        {
            datos = addFooterMessage(reference, validationUrl, reader, sout);
        }

        datos = addSignaturePlaceholders(datos, numSignatures);

        sout = addVisibleSignatureAndSign(signatureOptions, datos, certificate, caCertificate, numSignatures);

        SignatureResult signatureResult = new SignatureResult();
        signatureResult.setValid(true);
        signatureResult.setSignatureData(new ByteArrayInputStream(sout.toByteArray()));

        return signatureResult;
    }

    private ByteArrayOutputStream addVisibleSignatureAndSign(SignatureOptions signatureOptions, byte[] datos, X509Certificate certificate, Certificate caCertificate, int numSignatures) throws Exception
    {
        PdfReader reader;
        ByteArrayOutputStream sout;
        reader = new PdfReader(datos);
        sout = new ByteArrayOutputStream();

        PdfStamper pdfStamper = PdfStamper.createSignature(reader, sout, '\0', null, true);
        PdfSignatureAppearance pdfSignatureAppareance = pdfStamper.getSignatureAppearance();

        log.debug("VisibleSignature: " + confAdapter.isVisibleSignature());

        if (confAdapter.isVisibleSignature())
        {
            String pattern = confAdapter.getVisibleAreaTextPattern();
            log.debug("VisibleAreaTextPattern: " + pattern);

            Map<String, String> bindValues = generateBindValues(signatureOptions);

            createVisibleSignature(pdfSignatureAppareance, numSignatures, pattern, bindValues);
        }

        sign(pdfStamper, pdfSignatureAppareance, new Certificate[] { certificate, caCertificate });
        return sout;
    }

    private byte[] addSignaturePlaceholders(byte[] datos, int numSignatures) throws IOException, DocumentException
    {
        PdfReader reader;ByteArrayOutputStream sout;Rectangle rectangle = computeSignatureRectangle(numSignatures);

        reader = new PdfReader(datos);
        sout = new ByteArrayOutputStream();

        PdfStamper pdfStamper = new PdfStamper(reader, sout, '\0', true);

        PdfFormField sig1 = PdfFormField.createSignature(pdfStamper.getWriter());

        if (confAdapter.isVisibleSignature())
        {
            sig1.setWidget(rectangle, null);
            sig1.setFlags(PdfAnnotation.FLAGS_PRINT);
            sig1.put(PdfName.DA, new PdfString("/Helv 0 Tf 0 g"));
            sig1.setFieldName("CryptoAppletSignatureReference" + numSignatures);
            sig1.setPage(1);

            String visibleAreaPage = confAdapter.getVisibleAreaPage();

            if (visibleAreaPage == null || "ALL".equals(visibleAreaPage))
            {
                log.debug("Final visible page value: " + visibleAreaPage + ".");

                for (int pageNumber = 1; pageNumber <= reader.getNumberOfPages(); pageNumber++)
                {
                    log.debug("Generating annotation for page " + pageNumber);
                    pdfStamper.addAnnotation(sig1, pageNumber);
                }
            }
            else
            {
                int targetPage = 1;

                if ("LAST".equals(visibleAreaPage))
                {
                    targetPage = reader.getNumberOfPages();
                }
                else
                {
                    targetPage = Integer.valueOf(visibleAreaPage);
                }

                log.debug("Generating annotation for page " + targetPage);
                pdfStamper.addAnnotation(sig1, targetPage);
            }
        }

        pdfStamper.close();
        sout.close();

        datos = sout.toByteArray();
        return datos;
    }

    private byte[] addFooterMessage(String reference, String validationUrl, PdfReader reader, ByteArrayOutputStream sout) throws DocumentException, IOException
    {
        byte[] datos;
        String footerMessage = "";

        if (validationUrl != null)
        {
            footerMessage = MessageFormat.format(
                    "Puede validar este documento en {1} introduciendo la referencia {0}",
                    reference, validationUrl);

        }
        else
        {
            footerMessage = MessageFormat.format("La referencia de este documento es {0}",
                    reference, validationUrl);
        }

        PdfStamper stamper = new PdfStamper(reader, sout);
        PdfContentByte canvas = stamper.getOverContent(1);

        Font font = new Font(BaseFont.createFont(BaseFont.TIMES_ROMAN, "Cp1252", false));
        font.setSize(9);

        ColumnText.showTextAligned(canvas, Element.ALIGN_LEFT, new Phrase(footerMessage,
                font), 20, 20, 0);
        stamper.close();

        datos = sout.toByteArray();
        return datos;
    }

    private Rectangle computeSignatureRectangle(int numSignatures)
    {
        float x1 = confAdapter.getVisibleAreaX();
        float y1 = confAdapter.getVisibleAreaY();
        float x2 = confAdapter.getVisibleAreaX2();
        float y2 = confAdapter.getVisibleAreaY2();

        float offsetX = ((x2 - x1) * numSignatures) + 10;
        float offsetY = ((y2 - y1) * numSignatures) + 10;

        log.debug("VisibleArea: " + x1 + "," + y1 + "," + x2 + "," + y2 + " offsetX:" + offsetX
                + ", offsetY:" + offsetY);

        // Position of the visible signature

        Rectangle rectangle = null;

        if (confAdapter.getVisibleAreaRepeatAxis().equals("Y"))
        {
            rectangle = new Rectangle(x1, y1 + offsetY, x2, y2 + offsetY);
        }
        else
        {
            rectangle = new Rectangle(x1 + offsetX, y1, x2 + offsetX, y2);
        }
        return rectangle;
    }

    private Map<String, String> generateBindValues(SignatureOptions signatureOptions)
            throws CertificateEncodingException, NoSuchAlgorithmException
    {
        Map<String, String> bindValues = signatureOptions.getVisibleSignatureTextBindValues();
        X509Certificate certificate = signatureOptions.getCertificate();

        if (bindValues != null)
        {
            final X509Principal principal = PrincipalUtil.getSubjectX509Principal(certificate);
            final Vector<?> values = principal.getValues(X509Name.CN);

            String certificateCN = (String) values.get(0);
            bindValues.put("%s", certificateCN);

            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
            String currentDate = simpleDateFormat.format(new Date());
            bindValues.put("%t", currentDate);

            String pdfReason = this.confAdapter.getReason();
            bindValues.put("%reason", pdfReason);

            String pdfLocation = this.confAdapter.getLocation();
            bindValues.put("%location", pdfLocation);

            String pdfContact = this.confAdapter.getContact();
            bindValues.put("%contact", pdfContact);

            MessageDigest sha1 = MessageDigest.getInstance("SHA1");
            sha1.update(certificate.getEncoded());
            byte[] sha1Digest = sha1.digest();

            String certificateHash = new String(Hex.encode(sha1Digest));
            String certificateHashWithColons = certificateHash.replaceAll("(?<=..)(..)", ":$1");

            bindValues.put("%certificateHash", certificateHashWithColons);
        }

        for (Map.Entry<String, String> bindValue : bindValues.entrySet())
        {
            log.debug("Bind value " + bindValue.getKey() + ": " + bindValue.getValue());
        }

        return bindValues;
    }
}