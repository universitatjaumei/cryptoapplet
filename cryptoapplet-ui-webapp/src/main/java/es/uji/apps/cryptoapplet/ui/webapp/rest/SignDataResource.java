package es.uji.apps.cryptoapplet.ui.webapp.rest;

import es.uji.apps.cryptoapplet.ui.webapp.model.DataDocument;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

@Path("data")
public class SignDataResource
{
    @GET
    @Produces(MediaType.APPLICATION_XML)
    public DataDocument getData()
    {
        DataDocument document = new DataDocument();
        document.setId(1L);
        document.setName("Signature test");

        return document;
    }
}
