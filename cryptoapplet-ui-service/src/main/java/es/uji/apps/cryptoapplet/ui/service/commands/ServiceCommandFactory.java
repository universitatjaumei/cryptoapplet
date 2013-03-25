package es.uji.apps.cryptoapplet.ui.service.commands;

import es.uji.apps.cryptoapplet.ui.service.Request;

public class ServiceCommandFactory
{
    public static ServiceCommand buildCommand(Request request) throws Exception
    {
        String path = request.getPath();

        if ("/services/certificates".equals(path))
        {
            return new CertificateListCommand();
        }

        if ("/services/sign/raw".equals(path))
        {
            return new SignRawCommand(request.getData(), request.getQueryParams());
        }

        if ("/services/sign/xades".equals(path))
        {
            return new SignXadesCommand(request.getData(), request.getQueryParams());
        }

        throw new RuntimeException("Command not defined");
    }
}