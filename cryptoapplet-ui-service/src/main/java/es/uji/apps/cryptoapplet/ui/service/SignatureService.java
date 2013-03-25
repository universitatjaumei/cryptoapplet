package es.uji.apps.cryptoapplet.ui.service;

import es.uji.apps.cryptoapplet.ui.service.commands.ServiceCommand;
import es.uji.apps.cryptoapplet.ui.service.commands.ServiceCommandFactory;

import java.io.DataOutputStream;
import java.net.Socket;

public class SignatureService
{
    public void doService(Socket connection) throws Exception
    {
        Request request = new Request(connection.getInputStream());

        if (request.isValid())
        {
            ServiceCommand command = ServiceCommandFactory.buildCommand(request);
            DataObject data = command.execute();

            Response response = new Response(request.getCallBack());
            String responseText = response.build(data);

            DataOutputStream writer = new DataOutputStream(connection.getOutputStream());
            writer.writeBytes(responseText);
            writer.flush();
            writer.close();
        }
    }
}
