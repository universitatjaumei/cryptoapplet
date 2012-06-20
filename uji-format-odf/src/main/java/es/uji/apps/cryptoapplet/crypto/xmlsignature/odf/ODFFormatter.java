package es.uji.apps.cryptoapplet.crypto.xmlsignature.odf;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.sun.org.apache.xml.internal.security.Init;
import com.sun.org.apache.xml.internal.security.c14n.Canonicalizer;

import es.uji.apps.cryptoapplet.crypto.CryptoAppletCoreException;
import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureOptions; 
import es.uji.apps.cryptoapplet.crypto.SignatureResult;

public class ODFFormatter implements Formatter
{
    private static String OPENDOCUMENT_NAMESPACE = "urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0";

    @Override
    @SuppressWarnings("restriction")
    public SignatureResult format(SignatureOptions signatureOptions)
            throws CryptoAppletCoreException
    {
        try
        {
            // Acceso a los ficheros contenidos en el ODF
            ODFDocument odt = new ODFDocument(signatureOptions.getDataToSign());

            // Parseo de documentos XML
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();

            // Inicializamos las funciones criptográficas
            Init.init();

            // Definiciones funciones de firma
            MessageDigest md = MessageDigest.getInstance("SHA1");

            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

            DigestMethod dm = fac.newDigestMethod(DigestMethod.SHA1, null);

            Transform transform = fac.newTransform(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS,
                    (TransformParameterSpec) null);
            List<Transform> transformList = new ArrayList<Transform>();
            transformList.add(transform);

            CanonicalizationMethod cm = fac.newCanonicalizationMethod(
                    CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);

            SignatureMethod sm = fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null);

            // Referencias de la firma a los ficheros del ODF
            List<Reference> referenceList = new ArrayList<Reference>();

            // Acceso al manifest.xml y a la lista de elementos que contiene
            InputStream manifest = new ByteArrayInputStream(odt.getEntry("META-INF/manifest.xml"));
            Document docManifest = documentBuilder.parse(manifest);
            Element rootManifest = docManifest.getDocumentElement();
            NodeList listFileEntry = rootManifest.getElementsByTagName("manifest:file-entry");

            for (int i = 0; i < listFileEntry.getLength(); i++)
            {
                String fullPath = ((Element) listFileEntry.item(i))
                        .getAttribute("manifest:full-path");

                Reference reference;

                // Solo procesamos los ficheros
                if (!fullPath.endsWith("/") && !fullPath.equals("META-INF/documentsignatures.xml"))
                {
                    if (fullPath.equals("content.xml") || fullPath.equals("meta.xml")
                            || fullPath.equals("styles.xml") || fullPath.equals("settings.xml"))
                    {
                        // Obtenemos el fichero, canonizamos y calculamos el digest
                        InputStream xmlFile = new ByteArrayInputStream(odt.getEntry(fullPath));
                        Element root = documentBuilder.parse(xmlFile).getDocumentElement();

                        Canonicalizer canonicalizer = Canonicalizer
                                .getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
                        byte[] docCanonicalize = canonicalizer.canonicalizeSubtree(root);
                        byte[] digestValue = md.digest(docCanonicalize);

                        reference = fac.newReference(fullPath.replaceAll(" ", "%20"), dm,
                                transformList, null, null, digestValue);
                    }
                    else
                    {
                        // No es un XML. Solo calculamos el digest
                        byte[] digestValue = md.digest(odt.getEntry(fullPath));

                        reference = fac.newReference(fullPath.replaceAll(" ", "%20"), dm, null,
                                null, null, digestValue);
                    }

                    referenceList.add(reference);
                }
            }

            Document docSignatures;
            Element rootSignatures;

            // Si existe ya un documento lo recuperamos para añadir la firma, sino creamos uno
            if (odt.hasEntry("META-INF/documentsignatures.xml"))
            {
                InputStream xmlFile = new ByteArrayInputStream(
                        odt.getEntry("META-INF/documentsignatures.xml"));
                docSignatures = documentBuilder.parse(xmlFile);
                rootSignatures = docSignatures.getDocumentElement();
            }
            else
            {
                docSignatures = documentBuilder.newDocument();
                rootSignatures = docSignatures.createElement("document-signatures");
                rootSignatures.setAttribute("xmlns", OPENDOCUMENT_NAMESPACE);
                docSignatures.appendChild(rootSignatures);

                // Añadimos el fichero de firma al manifest.xml
                Element nodeDocumentSignatures = docManifest.createElement("manifest:file-entry");
                nodeDocumentSignatures.setAttribute("manifest:media-type", "");
                nodeDocumentSignatures.setAttribute("manifest:full-path",
                        "META-INF/documentsignatures.xml");
                rootManifest.appendChild(nodeDocumentSignatures);

                Element nodeMetaInf = docManifest.createElement("manifest:file-entry");
                nodeMetaInf.setAttribute("manifest:media-type", "");
                nodeMetaInf.setAttribute("manifest:full-path", "META-INF/");
                rootManifest.appendChild(nodeMetaInf);
            }

            // IDs de Signature y SignatureProperty
            String signatureId = UUID.randomUUID().toString();
            String signaturePropertyId = UUID.randomUUID().toString();

            // Referencia a SignatureProperty
            Reference signaturePropertyReference = fac.newReference("#" + signaturePropertyId, dm);
            referenceList.add(signaturePropertyReference);

            // SignedInfo
            SignedInfo si = fac.newSignedInfo(cm, sm, referenceList);

            // KeyInfo
            X509Certificate certificate = signatureOptions.getCertificate();

            KeyInfoFactory kif = fac.getKeyInfoFactory();
            List<Object> x509Content = new ArrayList<Object>();
            x509Content.add(certificate.getSubjectX500Principal().getName());
            x509Content.add(certificate);
            X509Data cerData = kif.newX509Data(x509Content);
            KeyInfo ki = kif.newKeyInfo(Collections.singletonList(cerData), null);

            // Contenido de SignatureProperty
            Element content = docSignatures.createElement("dc:date");
            content.setAttribute("xmlns:dc", "http://purl.org/dc/elements/1.1/");
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss,SS");
            content.setTextContent(sdf.format(new Date()));
            XMLStructure str = new DOMStructure(content);
            List<XMLStructure> contentList = new ArrayList<XMLStructure>();
            contentList.add(str);

            // SignatureProperty
            SignatureProperty sp = fac.newSignatureProperty(contentList, "#" + signatureId,
                    signaturePropertyId);
            List<SignatureProperty> spList = new ArrayList<SignatureProperty>();
            spList.add(sp);

            // SignatureProperties
            SignatureProperties sps = fac.newSignatureProperties(spList, null);
            List<SignatureProperties> spsList = new ArrayList<SignatureProperties>();
            spsList.add(sps);

            // Object
            XMLObject object = fac.newXMLObject(spsList, null, null, null);
            List<XMLObject> objectList = new ArrayList<XMLObject>();
            objectList.add(object);

            XMLSignature signature = fac.newXMLSignature(si, ki, objectList, signatureId, null);
            DOMSignContext signContext = new DOMSignContext(signatureOptions.getPrivateKey(),
                    rootSignatures);
            signature.sign(signContext);

            // Generacion del ODF de salida
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ZipOutputStream zos = new ZipOutputStream(baos);

            // Copiar el contenido existente al ODF de salida
            for (String fileName : odt.getFileList())
            {
                ZipEntry zeOut = new ZipEntry(fileName);

                if (!fileName.equals("META-INF/documentsignatures.xml")
                        && !fileName.equals("META-INF/manifest.xml"))
                {
                    zos.putNextEntry(zeOut);
                    zos.write(odt.getEntry(fileName));
                }
            }

            // Añadimos el documento de firmas al ODF de salida
            ZipEntry zeDocumentSignatures = new ZipEntry("META-INF/documentsignatures.xml");
            zos.putNextEntry(zeDocumentSignatures);
            ByteArrayOutputStream baosXML = new ByteArrayOutputStream();
            writeXML(baosXML, rootSignatures, false);
            zos.write(baosXML.toByteArray());
            zos.closeEntry();

            // Añadimos el manifest.xml al ODF de salida
            ZipEntry zeManifest = new ZipEntry("META-INF/manifest.xml");
            zos.putNextEntry(zeManifest);
            ByteArrayOutputStream baosManifest = new ByteArrayOutputStream();
            writeXML(baosManifest, rootManifest, false);
            zos.write(baosManifest.toByteArray());
            zos.closeEntry();

            zos.close();

            SignatureResult signatureResult = new SignatureResult();
            signatureResult.setValid(true);
            signatureResult.setSignatureData(new ByteArrayInputStream(baos.toByteArray()));

            return signatureResult;
        }
        catch (IOException ioex)
        {
            SignatureResult signatureResult = new SignatureResult();
            signatureResult.setValid(false);
            signatureResult.addError("No es posible abrir el fichero " + ioex.toString());

            return signatureResult;
        }
        catch (SAXException saxex)
        {
            SignatureResult signatureResult = new SignatureResult();
            signatureResult.setValid(false);
            signatureResult.addError("Estructura de archivo no valida: " + saxex.toString());

            return signatureResult;
        }
        catch (Exception e)
        {
            SignatureResult signatureResult = new SignatureResult();
            signatureResult.setValid(false);
            signatureResult.addError("No ha sido posible generar la firma ODF. " + e.toString());

            return signatureResult;
        }
    }

    private static void writeXML(OutputStream outStream, Node node, boolean indent)
            throws TransformerFactoryConfigurationError, TransformerException
    {
        writeXML(new BufferedWriter(new OutputStreamWriter(outStream, Charset.forName("UTF-8"))),
                node, indent);
    }

    private static void writeXML(Writer writer, Node node, boolean indent)
            throws TransformerFactoryConfigurationError, TransformerException
    {
        Transformer serializer = TransformerFactory.newInstance().newTransformer();
        serializer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

        if (indent)
        {
            serializer.setOutputProperty(OutputKeys.INDENT, "yes");
        }
        serializer.transform(new DOMSource(node), new StreamResult(writer));
    }
}