package es.uji.apps.cryptoapplet.ui.applet;

//import org.mockito.Mockito;
//
//import es.uji.apps.cryptoapplet.crypto.BrowserType;
//import es.uji.apps.cryptoapplet.crypto.DataEncoding;
//import es.uji.apps.cryptoapplet.crypto.SignatureFormat;
//
//public class SignatureAppletTest
//{
//    public static void main(String[] args)
//    {
//        JSCommands jsCommands = Mockito.mock(JSCommands.class);
//        Mockito.when(jsCommands.getSupportedBrowser()).thenReturn(BrowserType.FIREFOX);
//
//        SignatureApplet signatureApplet = new SignatureApplet(jsCommands);
//        signatureApplet.init();
//        signatureApplet.setInputDataEncoding(DataEncoding.PLAIN.name());
//        signatureApplet.setOutputSignatureFormat(SignatureFormat.XADES.name());
//        signatureApplet.showUI();
//    }
//}