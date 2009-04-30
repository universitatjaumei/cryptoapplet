//package es.uji.security.crypto.openxades.test;
//
//import java.io.File;
//import java.io.InputStream;
//import java.io.OutputStream;
//import java.net.URL;
//import java.net.URLConnection;
//import java.security.PrivateKey;
//import java.security.cert.Certificate;
//import java.security.cert.X509Certificate;
//import java.util.ArrayList;
//import java.util.Enumeration;
//
//import org.bouncycastle.tsp.TSPAlgorithms;
//import org.bouncycastle.tsp.TimeStampRequest;
//import org.bouncycastle.tsp.TimeStampRequestGenerator;
//import org.bouncycastle.tsp.TimeStampResponse;
//
//import es.uji.security.crypto.SHA1Digest;
//import es.uji.security.crypto.openxades.XAdESSignatureFactory;
//import es.uji.security.crypto.openxades.digidoc.CertValue;
//import es.uji.security.crypto.openxades.digidoc.DataFile;
//import es.uji.security.crypto.openxades.digidoc.DigiDocException;
//import es.uji.security.crypto.openxades.digidoc.Signature;
//import es.uji.security.crypto.openxades.digidoc.SignedDoc;
//import es.uji.security.crypto.openxades.digidoc.TimestampInfo;
//import es.uji.security.crypto.openxades.digidoc.factory.DigiDocFactory;
//import es.uji.security.crypto.openxades.digidoc.utils.ConfigManager;
//import es.uji.security.crypto.openxades.digidoc.utils.ConvertUtils;
//
//public class CoSignTest
//{
//
//    /**
//     * @param args
//     */
//    public static void main(String[] args)
//    {
//        // TODO Auto-generated method stub
//        try
//        {
//            XAdESSignatureFactory XFact = new XAdESSignatureFactory();
//
//            MozillaKeyStore mks = new MozillaKeyStore();
//            mks.load("TU PIN AQUI".toCharArray());
//
//            Enumeration en = mks.aliases();
//            String alias = (String) en.nextElement();
//
//            // Leemos el fichero de configuracion
//            ConfigManager.init("/tmp/jdigidoc.cfg");
//            // log.debug("JDigidoc configuration file loaded");
//
//            // Creamos un nuevo SignedDoc XAdES
//            // SignedDoc sdoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);
//
//            // Añadimos una nueva referencia de fichero en base64 ... aunque establecemos el body
//            // DataFile df = sdoc.addDataFile(new File("/tmp/data.xml"), "application/binary",
//            // DataFile.CONTENT_EMBEDDED_BASE64);
//            // df.setBody(ConvertUtils.str2data("hola como estamos"), "UTF8");
//
//            DigiDocFactory digFac = ConfigManager.instance().getDigiDocFactory();
//
//            SignedDoc sdoc = digFac.readSignedDoc("/home/paul/data.ddoc");
//
//            sign(sdoc, mks, alias);
//
//            sdoc.writeToFile(new File("/home/paul/x.ddoc"));
//            // alias= (String) en.nextElement();
//            // sign(sdoc,mks,alias);
//
//        }
//        catch (Exception e)
//        {
//            e.printStackTrace();
//        }
//    }
//
//    public static void sign(SignedDoc sdoc, MozillaKeyStore mks, String alias)
//    {
//        Certificate cert = null;
//
//        try
//        {
//            cert = mks.getCertificate(alias);
//
//            PrivateKey privKey = (PrivateKey) mks.getKey(alias);
//
//            Signature sig = sdoc.prepareSignature((X509Certificate) cert, new String[] { "PDI" },
//                    null);
//
//            // Firmamos
//            byte[] sidigest = sig.getSignedContent();
//            java.security.Signature rsa = java.security.Signature.getInstance("SHA1withRSA", mks
//                    .getProvider());
//            rsa.initSign(privKey);
//            rsa.update(sidigest);
//            byte[] res = rsa.sign();
//
//            // Añadimos la firma al SignedDoc
//            sig.setSignatureValue(res);
//
//            // Obtenemos el timestamp y lo añadimos
//            TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
//
//            // Request TSA to return certificate
//            reqGen.setCertReq(false);
//
//            SHA1Digest sha = new SHA1Digest();
//            sha.engineUpdate(sig.getSignatureValue().toString().getBytes(), 0, sig
//                    .getSignatureValue().toString().length());
//
//            byte[] hash = sha.engineDigest();
//
//            TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, hash);
//            byte[] enc_req = request.getEncoded();
//
//            String tsaUrl = ConfigManager.instance().getProperty("DIGIDOC_TSA1_URL");
//            URL url = new URL(tsaUrl);
//
//            URLConnection urlConn = url.openConnection();
//            urlConn.setDoInput(true);
//            urlConn.setDoOutput(true);
//            urlConn.setUseCaches(false);
//
//            urlConn.setRequestProperty("Content-Type", "application/timestamp-query");
//            urlConn.setRequestProperty("Content-Length", "" + enc_req.length);
//
//            OutputStream printout = urlConn.getOutputStream();
//            printout.write(enc_req);
//            printout.flush();
//            printout.close();
//
//            InputStream in = urlConn.getInputStream();
//
//            TimeStampResponse resp = new TimeStampResponse(in);
//
//            resp.validate(request);
//
//            // log.debug("Timestamp validated");
//
//            TimestampInfo ts = new TimestampInfo("TS2", TimestampInfo.TIMESTAMP_TYPE_SIGNATURE);
//            ts.setTimeStampResponse(resp);
//            ts.setSignature(sig);
//            ts.setHash(resp.getTimeStampToken().getTimeStampInfo().getMessageImprintDigest());
//
//            sig.addTimestampInfo(ts);
//
//            String tsa1_ca = ConfigManager.instance().getProperty("DIGIDOC_TSA1_CA_CERT");
//            X509Certificate xcaCert = SignedDoc.readCertificate(tsa1_ca);
//
//            CertValue cval = new CertValue();
//            cval.setType(CertValue.CERTVAL_TYPE_TSA);
//            cval.setCert(xcaCert);
//            cval.setId(sig.getId() + "-TSA_CERT");
//
//            // Añadimos certificado TSA
//            sig.addCertValue(cval);
//
//            // Verificación OCSP
//            sig.getConfirmation();
//
//            System.out.println("SIGNED DOC: " + sdoc.toXML());
//            String xadesFile = System.getProperty("user.home")
//                    + System.getProperty("file.separator") + "data_gen.ddoc";
//            sdoc.writeToFile(new File(xadesFile));
//        }
//        catch (Exception e)
//        {
//            e.printStackTrace();
//        }
//    }
//
//    public void verifyDoc()
//    {
//        // TODO: Eliminar, solo desarrollo
//        {
//
//            try
//            {
//                // Verificamos el documento creado
//                DigiDocFactory digFac = ConfigManager.instance().getDigiDocFactory();
//
//                String xadesFile = System.getProperty("user.home")
//                        + System.getProperty("file.separator") + "data.ddoc";
//
//                SignedDoc sdoc = digFac.readSignedDoc(xadesFile);
//
//                for (int i = 0; i < sdoc.countSignatures(); i++)
//                {
//                    Signature sig = sdoc.getSignature(i);
//                    ArrayList errs = sig.verify(sdoc, false, false);
//
//                    if (errs.size() == 0 || (errs.size() == 1 && errs.get(0) == null))
//                    {
//                        System.out.println("XAdES document is correct!!!");
//                    }
//                    else
//                    {
//                        for (int j = 0; j < errs.size(); j++)
//                        {
//                            System.out.println("JDigidoc Error: " + (DigiDocException) errs.get(i));
//                            System.out.println("JDigidoc Error size : " + errs.size());
//                        }
//                    }
//                }
//            }
//            catch (Exception e)
//            {
//                e.printStackTrace();
//            }
//        }
//    }
//}