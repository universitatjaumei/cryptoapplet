package es.uji.apps.cryptoapplet.ui.service;

import es.uji.apps.cryptoapplet.ui.service.commands.CertificateListCommand;
import es.uji.apps.cryptoapplet.ui.service.commands.Command;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;

public class SignatureService
{
    private DataObject getData(Request request) throws IOException, GeneralSecurityException
    {
        DataObject data = new DataObject();

        if (Command.certificates.equals(request.getCommand()))
        {
            data = new CertificateListCommand().execute();
        }

        return data;
    }

    public void doService(Socket connection) throws IOException, GeneralSecurityException
    {
        Request request = new Request(connection.getInputStream());

        if (request.isValid())
        {
            Response response = new Response(request.getCallBack());

            DataObject data = getData(request);
            String responseText = response.build(data);

            DataOutputStream writer = new DataOutputStream(connection.getOutputStream());
            writer.writeBytes(responseText);
            writer.flush();
            writer.close();
        }
    }
}
