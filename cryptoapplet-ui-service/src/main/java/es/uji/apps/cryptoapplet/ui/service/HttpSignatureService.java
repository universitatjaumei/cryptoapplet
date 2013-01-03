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

    public HttpSignatureService() throws IOException
    {
        initSocket();
    }

    private void initSocket() throws IOException
    {
        socket = new ServerSocket();
        socket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), PORT));
    }

    public void run()
    {
        SignatureService service = new SignatureService();

        while (true)
        {
            try
            {
                Socket connection = this.socket.accept();
                Request request = new Request(connection.getInputStream());

                if (request.isInvalid())
                {
                    continue;
                }

                service.doService(request, connection.getOutputStream());
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