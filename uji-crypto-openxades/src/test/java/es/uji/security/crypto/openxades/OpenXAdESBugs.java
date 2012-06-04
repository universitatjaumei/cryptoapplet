package es.uji.security.crypto.openxades;

import java.io.File;
import java.io.FileInputStream;

import org.junit.Before;
import org.junit.Test;

import es.uji.security.crypto.StreamUtils;
import es.uji.security.crypto.openxades.digidoc.DataFile;
import es.uji.security.crypto.openxades.digidoc.DigiDocException;
import es.uji.security.crypto.openxades.digidoc.SignedDoc;

public class OpenXAdESBugs
{
    @Before
    public void initVerificationErrorContentDettachedFile() throws DigiDocException
    {
        SignedDoc signedDoc = new SignedDoc(SignedDoc.FORMAT_DIGIDOC_XML, SignedDoc.VERSION_1_3);

        // Add a new reference in Bas64 and establish body data
        DataFile df = signedDoc.addDataFile(new File("jar://data.xml"), "text/xml",
                DataFile.CONTENT_EMBEDDED_BASE64);
        signedDoc.getDataFile(0).setFileName("data.xml");
        signedDoc.getDataFile(0).setMimeType("text/xml");
        df.setBody("<test/>".getBytes());
        df.setSize("<test/>".getBytes().length);

        signedDoc.addDataFile(new File("src/main/resources/in-openxades-error-dettached.xml"),
                "text/xml", DataFile.CONTENT_DETATCHED);
        signedDoc.getDataFile(1).setFileName("src/main/resources/in-openxades-error-dettached.xml");
        signedDoc.getDataFile(1).setMimeType("text/xml");

        signedDoc.writeToFile(new File("src/main/resources/out-openxades-error-dettached.xml"));
    }

    @Test
    public void verificationErrorContentDettached() throws Exception
    {
        byte[] data = StreamUtils.inputStreamToByteArray(new FileInputStream(
                "src/main/resources/out-openxades-error-dettached.xml"));

        OpenXAdESTest openXAdESTest = new OpenXAdESTest();
        openXAdESTest.setData(data);
        openXAdESTest.init();
        openXAdESTest.openxades();
    }
}
