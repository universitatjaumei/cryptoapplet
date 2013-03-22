package es.uji.apps.cryptoapplet.ui.service;

import es.uji.apps.cryptoapplet.ui.service.commands.CertificateListCommand;
import es.uji.apps.cryptoapplet.ui.service.commands.Command;
import es.uji.apps.cryptoapplet.ui.service.commands.SignCommand;

import java.io.DataOutputStream;
import java.net.Socket;

public class SignatureService
{
    private DataObject getData(Request request) throws Exception
    {
        if (Command.certificates.equals(request.getCommand()))
        {
            return new CertificateListCommand().execute();
        }

        if (Command.signraw.equals(request.getCommand()))
        {
            return new SignCommand(request.getData(), request.getQueryParams()).execute();
        }

        throw new RuntimeException("Command not defined");
    }

    public void doService(Socket connection) throws Exception
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
