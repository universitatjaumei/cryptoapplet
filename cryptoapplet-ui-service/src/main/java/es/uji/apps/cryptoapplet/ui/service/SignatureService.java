package es.uji.apps.cryptoapplet.ui.service;

import es.uji.apps.cryptoapplet.ui.service.commands.CertificateListCommand;
import es.uji.apps.cryptoapplet.ui.service.commands.Command;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

public class SignatureService
{
    public void doService(Request request, OutputStream outputStream) throws IOException, GeneralSecurityException
    {
        DataObject data = getData(request);

        Response response = new Response(request.getCallBack());
        String responseText = response.build(data);

        DataOutputStream writer = new DataOutputStream(outputStream);
        writer.writeBytes(responseText);
        writer.flush();
        writer.close();
    }

    private DataObject getData(Request request) throws IOException, GeneralSecurityException
    {
        DataObject data = new DataObject();

        if (Command.certificates.equals(request.getCommand()))
        {
            data = new CertificateListCommand().execute();
        }

        return data;
    }
}
