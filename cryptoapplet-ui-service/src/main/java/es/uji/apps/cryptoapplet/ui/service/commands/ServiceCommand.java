package es.uji.apps.cryptoapplet.ui.service.commands;

import es.uji.apps.cryptoapplet.config.ConfigurationLoadException;
import es.uji.apps.cryptoapplet.crypto.SignatureException;
import es.uji.apps.cryptoapplet.ui.service.DataObject;

public interface ServiceCommand
{
    public DataObject execute() throws Exception;
}
