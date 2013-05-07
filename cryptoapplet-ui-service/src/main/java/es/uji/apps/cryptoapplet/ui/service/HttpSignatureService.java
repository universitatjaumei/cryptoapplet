package es.uji.apps.cryptoapplet.ui.service;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class HttpSignatureService implements Runnable
{
    public static final int PORT = 12345;

    private ServerSocket socket;

    public HttpSignatureService()
    {
        initSocket();
    }

    private void initSocket()
    {
        try
        {
            socket = new ServerSocket();
            socket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), PORT));
        }
        catch (IOException e)
        {
            System.exit(0);
        }
    }

    public void run()
    {
        SignatureService service = new SignatureService();

        while (true)
        {
            try
            {
                Socket connection = this.socket.accept();
                service.doService(connection);
                connection.close();
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) throws IOException
    {
        new HttpSignatureService().run();
    }
}