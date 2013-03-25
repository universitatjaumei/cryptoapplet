package es.uji.apps.cryptoapplet.ui.service.commands;

import es.uji.apps.cryptoapplet.ui.service.DataObject;

public interface ServiceCommand
{
    public DataObject execute() throws Exception;
}
