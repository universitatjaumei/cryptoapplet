package es.uji.security.ui.applet;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Hashtable;

import javax.swing.*;

import org.junit.Test;

import es.uji.security.crypto.SupportedDataEncoding;
import es.uji.security.crypto.SupportedKeystore;
import es.uji.security.crypto.SupportedSignatureFormat;
import es.uji.security.crypto.config.OS;
import es.uji.security.keystore.IKeyStore;
import es.uji.security.keystore.KeyStoreManager;
import es.uji.security.keystore.pkcs12.PKCS12KeyStore;
import es.uji.security.ui.applet.io.InputParams;
import es.uji.security.ui.applet.io.OutputParams;
import es.uji.security.ui.applet.io.URLInputParams;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SignatureThreadTest
{
    @Test
    public void sign() throws Exception
    {
        PKCS12KeyStore keystore = new PKCS12KeyStore();
        keystore.load(new FileInputStream(System.getProperty("uji.keystore.file")),
                System.getProperty("uji.keystore.keypassword").toCharArray());

        Hashtable<SupportedKeystore, IKeyStore> keyStoreTable = new Hashtable<SupportedKeystore, IKeyStore>();
        keyStoreTable.put(SupportedKeystore.PKCS12, keystore);

        KeyStoreManager keyStoreManager = mock(KeyStoreManager.class);
        when(keyStoreManager.getKeyStoreTable()).thenReturn(keyStoreTable);

        AppHandler appHandler = mock(AppHandler.class);
        when(appHandler.getSignatureFormat()).thenReturn(SupportedSignatureFormat.PADES);
        when(appHandler.getInputDataEncoding()).thenReturn(SupportedDataEncoding.PLAIN);
        when(appHandler.getOutputDataEncoding()).thenReturn(SupportedDataEncoding.PLAIN);

        InputParams inputParams = new URLInputParams(new String[]{ "http://aris.si.uji.es:8080/in-pdf.pdf" });
        when(appHandler.getInputParams()).thenReturn(inputParams);
        when(appHandler.getInput()).thenReturn(inputParams);

        when(appHandler.getOutputParams()).thenReturn(new OutputParams()
        {
            @Override
            public void setSignFormat(byte[] signFormat) throws IOException
            {
                System.out.println(new String(signFormat));
            }

            @Override
            public void setSignData(InputStream data, int currentIndex) throws IOException
            {
                System.out.println("Output " + currentIndex);
                System.out.println(new String(OS.inputStreamToByteArray(data)));
            }

            @Override
            public void signOk()
            {
                System.out.println("signOk");
            }

            @Override
            public void flush()
            {
                System.out.println("flush");
            }
        });

        MainWindow mainWindow = new MainWindow(keyStoreManager, appHandler);
        when(appHandler.getMainWindow()).thenReturn(mainWindow);

        JTree jTree = mainWindow.getJTree();
        jTree.setSelectionPath(jTree.getPathForRow(2));

        SignatureHandler signatureHandler = new SignatureHandler(appHandler);
        signatureHandler.doSign();
    }
}
