package es.uji.apps.cryptoapplet.service.httpserver;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;

public class HttpServerTest
{
    public void serverShouldBeAvailableOnStart() throws IOException
    {
        class MyHandler implements HttpHandler
        {
            public void handle(HttpExchange t) throws IOException
            {
                InputStream is = t.getRequestBody();
                read(is); // .. read the request body

                String response = "{ data : 'hello' }";

                Headers headers = t.getResponseHeaders();
                headers.set("Content-type", "application/json");

                t.sendResponseHeaders(200, response.length());

                OutputStream os = t.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
        }

        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/services/certificates", new MyHandler());
        server.setExecutor(null); // creates a default executor
        server.start();
    }

    private void read(InputStream is)
    {
    }

    public static void main(String args[]) throws IOException
    {
        new HttpServerTest().serverShouldBeAvailableOnStart();
    }
}