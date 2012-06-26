package es.uji.apps.cryptoapplet.crypto.pdf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;

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

import es.uji.apps.cryptoapplet.config.model.Configuration;
import es.uji.apps.cryptoapplet.config.model.Format;
import es.uji.apps.cryptoapplet.config.model.TimestampingService;
import es.uji.apps.cryptoapplet.crypto.BaseFormatter;
import es.uji.apps.cryptoapplet.crypto.SignatureException;
import es.uji.apps.cryptoapplet.crypto.SignatureOptions;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.utils.StreamUtils;

public class PDFFormatter extends BaseFormatter implements
        es.uji.apps.cryptoapplet.crypto.Formatter
{
    private Logger log = Logger.getLogger(PDFFormatter.class);

    private X509Certificate[] chain;
    private Map<String, String> configuration;

    private Font font;

    public PDFFormatter(X509Certificate certificate, X509Certificate[] caCertificates,
            PrivateKey privateKey, Provider provider) throws SignatureException
    {
        super(certificate, caCertificates, privateKey, provider);
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

    private void sign(PdfStamper pdfStamper, PdfSignatureAppearance pdfSignatureAppearance,
            String tsaURL) throws Exception
    {
        // Check if TSA support is enabled

        boolean enableTSP = (tsaURL != null && !tsaURL.isEmpty());

        // Add configured values

        if (enableTSP)
        {
            PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKMS, PdfName.ADBE_PKCS7_SHA1);

            dic.setReason(configuration.get("reason"));
            dic.setLocation(configuration.get("location"));
            dic.setContact(configuration.get("contact"));
            dic.setDate(new PdfDate(pdfSignatureAppearance.getSignDate())); // time-stamp will
            // over-rule this

            pdfSignatureAppearance.setCryptoDictionary(dic);
            pdfSignatureAppearance.setCrypto((PrivateKey) privateKey, chain, null, null);

            int contentEst = 15000;

            HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
            exc.put(PdfName.CONTENTS, new Integer(contentEst * 2 + 2));
            pdfSignatureAppearance.preClose(exc);

            byte[] encodedSig = genPKCS7Signature(pdfSignatureAppearance.getRangeStream(), tsaURL,
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
            pdfSignatureAppearance.setReason(configuration.get("reason"));
            pdfSignatureAppearance.setLocation(configuration.get("location"));
            pdfSignatureAppearance.setContact(configuration.get("contact"));
            pdfStamper.close();
        }
    }

    private void createVisibleSignature(PdfSignatureAppearance sap, int numSignatures,
            String pattern, Map<String, String> bindValues) throws MalformedURLException,
            IOException, DocumentException
    {
        float x1 = Float.parseFloat(configuration.get("signature.x"));
        float y1 = Float.parseFloat(configuration.get("signature.y"));
        float x2 = Float.parseFloat(configuration.get("signature.x2"));
        float y2 = Float.parseFloat(configuration.get("signature.y2"));

        float offsetX = ((x2 - x1) * numSignatures) + 10;
        float offsetY = ((y2 - y1) * numSignatures) + 10;

        log.debug("VisibleArea: " + x1 + "," + y1 + "," + x2 + "," + y2 + " offsetX:" + offsetX
                + ", offsetY:" + offsetY);

        // Position of the visible signature

        Rectangle rectangle = null;

        if ("Y".equalsIgnoreCase(configuration.get("signature.repeatAxis")))
        {
            rectangle = new Rectangle(x1, y1 + offsetY, x2, y2 + offsetY);
        }
        else
        {
            rectangle = new Rectangle(x1 + offsetX, y1, x2 + offsetX, y2);
        }

        sap.setVisibleSignature(rectangle, Integer.parseInt(configuration.get("signature.page")),
                null);
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

        String signatureType = configuration.get("signature.type");
        log.debug("VisibleSignatureType: " + signatureType);

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

        byte[] imageData = StreamUtils.inputStreamToByteArray(PDFFormatter.class.getClassLoader()
                .getResourceAsStream(configuration.get("signature.imgFile")));
        Image image = Image.getInstance(imageData);

        if (signatureText != null)
        {
            // Retrieve and reset Layer2

            PdfTemplate pdfTemplate = pdfSignatureAppearance.getLayer(2);
            pdfTemplate.reset();

            float width = Math.abs(rectangle.getWidth());
            float height = Math.abs(rectangle.getHeight());

            pdfTemplate.addImage(image, height, 0, 0, height, 3, 3);

            // Add text

            ColumnText ct = new ColumnText(pdfTemplate);
            ct.setRunDirection(PdfWriter.RUN_DIRECTION_DEFAULT);
            ct.setSimpleColumn(new Phrase(signatureText, font), height + 3 * 2, 0, width - 3,
                    height, font.getSize(), Element.ALIGN_LEFT);
            ct.go();
        }
        else
        {
            pdfSignatureAppearance.setSignatureGraphic(image);
        }
    }

    @Override
    public SignatureResult format(SignatureOptions signatureOptions) throws SignatureException
    {
        checkSignatureOptions(signatureOptions);

        Configuration configuration = signatureOptions.getConfiguration();
        Format formatter = configuration.getFormatRegistry().getFormat("PDF");
        this.configuration = formatter.getConfiguration();

        log.debug("Init PDF signature configuration");

        font = new Font();
        font.setSize(Float.parseFloat(this.configuration.get("signature.textSize")));

        try
        {
            X509Certificate cert = certificate;
            X509Certificate CACert = null;

            for (X509Certificate caCertificate : caCertificates)
            {
                try
                {
                    cert.verify(caCertificate.getPublicKey());
                    CACert = caCertificate;
                    break;
                }
                catch (Exception e)
                {
                    // The actual CACert does not match with the
                    // signer certificate.
                    CACert = null;
                }
            }

            if (CACert == null)
            {
                throw new CanNotBuildCertificateChainException();
            }

            chain = new X509Certificate[] { cert, CACert };

            // Begin with the signature itself

            PdfReader reader = new PdfReader(signatureOptions.getDataToSign());
            ByteArrayOutputStream sout = new ByteArrayOutputStream();

            PdfStamper pdfStamper = PdfStamper.createSignature(reader, sout, '\0', null, true);
            PdfSignatureAppearance pdfSignatureAppareance = pdfStamper.getSignatureAppearance();

            boolean isVisibleSignature = "true".equalsIgnoreCase(this.configuration
                    .get("signature.visible"));

            if (isVisibleSignature)
            {
                String pattern = this.configuration.get("signature.textPattern");
                log.debug("VisibleAreaTextPattern: " + pattern);

                // TODO Bind values support on config options
                Map<String, String> bindValues = new HashMap<String, String>();

                if (bindValues != null)
                {
                    final X509Principal principal = PrincipalUtil
                            .getSubjectX509Principal(certificate);
                    final Vector<?> values = principal.getValues(X509Name.CN);

                    String certificateCN = (String) values.get(0);
                    bindValues.put("%s", certificateCN);
                    log.debug("Bind value %s: " + certificateCN);

                    SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
                    String currentDate = simpleDateFormat.format(new Date());
                    bindValues.put("%t", currentDate);
                    log.debug("Bind value %t: " + currentDate);
                }

                int numSignatures = reader.getAcroFields().getSignatureNames().size();

                createVisibleSignature(pdfSignatureAppareance, numSignatures, pattern, bindValues);
            }

            TimestampingService timestampingService = configuration.getTimestampingServicesRegistry()
                    .getTimestampingService(formatter.getTsaId());

            sign(pdfStamper, pdfSignatureAppareance, timestampingService.getUrl());

            SignatureResult signatureResult = new SignatureResult(true);
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
