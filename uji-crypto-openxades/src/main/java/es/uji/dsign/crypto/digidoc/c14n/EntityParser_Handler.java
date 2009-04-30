package es.uji.dsign.crypto.digidoc.c14n;

import es.uji.dsign.crypto.digidoc.c14n.EntityParser_Entity;

public abstract interface EntityParser_Handler
{




    abstract public String ResolveEntity(EntityParser_Entity e);

    abstract public String ResolveText(String e);

}
