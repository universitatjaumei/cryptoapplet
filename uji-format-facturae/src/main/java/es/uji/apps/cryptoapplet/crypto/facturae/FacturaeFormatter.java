package es.uji.apps.cryptoapplet.crypto.facturae;

import java.io.ByteArrayInputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import es.uji.apps.cryptoapplet.crypto.CryptoAppletCoreException;
import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureOptions;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.crypto.xades.XAdESFormatter;
import es.uji.apps.cryptoapplet.utils.StreamUtils;

public class FacturaeFormatter implements Formatter
{
    @Override
    public SignatureResult format(SignatureOptions signatureOptions)
            throws CryptoAppletCoreException
    {
        byte[] data = StreamUtils.inputStreamToByteArray(signatureOptions.getDataToSign());

        try
        {
            // Check if input data is already signed
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();

            Document document = documentBuilder.parse(new ByteArrayInputStream(data));

            NodeList result = document.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#",
                    "Signature");
            int numSignatures = result.getLength();

            if (numSignatures > 0)
            {
                SignatureResult signatureResult = new SignatureResult();
                signatureResult.setValid(false);
                signatureResult.addError("CoSign for Facturae not supported");

                return signatureResult;
            }

            // Call jXAdES format signature
            signatureOptions.setCoSignEnabled(false);
            signatureOptions
                    .setPolicyIdentifier("http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf");
            signatureOptions
                    .setPolicyDescription("Pol\u00edtica de firma electr\u00f3nica para facturaci\u00f3n electr\u00f3nica con formato Facturae");
            /*
             * signatureOptions .setPolicyDescription("facturae31");
             */
            signatureOptions.setDataToSign(new ByteArrayInputStream(data));

            XAdESFormatter formatter = new XAdESFormatter();

            return formatter.format(signatureOptions);
        }
        catch (Exception e)
        {
            throw new CryptoAppletCoreException(e);
        }
    }
}
