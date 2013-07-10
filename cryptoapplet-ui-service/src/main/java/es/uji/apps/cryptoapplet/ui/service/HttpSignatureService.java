//package es.uji.apps.cryptoapplet.ui.service;
//
//import java.io.File;
//import java.io.FileInputStream;
//import java.io.FileNotFoundException;
//import java.io.IOException;
//import java.net.InetAddress;
//import java.net.InetSocketAddress;
//import java.net.ServerSocket;
//import java.net.Socket;
//import javax.swing.*;
//import es.uji.apps.cryptoapplet.utils.StreamUtils;
//import es.uji.apps.cryptoapplet.ui.service.ui.PasswordManagementWindow;
//
//public class HttpSignatureService implements Runnable
//{
//    public static final String CRYPTOAPPLET_AUTH_TOKEN = System.getProperty("user.home") + "/.cryptoapplet-auth-token";
//    public static final int PORT = 12345;
//
//    private ServerSocket socket;
//    private String password;
//
//    public HttpSignatureService()
//    {
//        initSocket();
//        managePassword();
//    }
//
//    private void managePassword()
//    {
//        if (credentialsCanBeRetrieved())
//        {
//            return;
//        }
//
//        SwingUtilities.invokeLater(new Runnable()
//        {
//            public void run()
//            {
//                new PasswordManagementWindow();
//            }
//        });
//    }
//
//    private boolean credentialsCanBeRetrieved()
//    {
//        boolean fileExist = new File(CRYPTOAPPLET_AUTH_TOKEN).exists();
//        boolean passwordCouldBeRetrieved = false;
//
//        try
//        {
//            byte[] passwordData = StreamUtils.inputStreamToByteArray(new FileInputStream(CRYPTOAPPLET_AUTH_TOKEN));
//
//            if (passwordData != null && passwordData.length > 0)
//            {
//                passwordCouldBeRetrieved = true;
//                this.password = new String(passwordData);
//            }
//        }
//        catch (FileNotFoundException e)
//        {
//            return false;
//        }
//
//        return fileExist && passwordCouldBeRetrieved;
//    }
//
//    private void initSocket()
//    {
//        try
//        {
//            socket = new ServerSocket();
//            socket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), PORT));
//        }
//        catch (IOException e)
//        {
//            JOptionPane.showMessageDialog(null, "El servicio de firma de CryptoApplet ya había sido iniciado con anterioridad");
//            System.exit(0);
//        }
//    }
//
//    public void run()
//    {
//        SignatureService service = new SignatureService();
//
//        while (true)
//        {
//            try
//            {
//                Socket connection = this.socket.accept();
//                service.doService(connection);
//                connection.close();
//            }
//            catch (Exception e)
//            {
//                e.printStackTrace();
//            }
//        }
//    }
//
//    public static void main(String[] args) throws IOException
//    {
//        new HttpSignatureService().run();
//    }
//}