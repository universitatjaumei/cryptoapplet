package es.uji.security.crypto.openxades.digidoc.c14n;

import es.uji.security.crypto.openxades.digidoc.c14n.EntityParser_Entity;

public abstract interface EntityParser_Handler
{

    abstract public String ResolveEntity(EntityParser_Entity e);

    abstract public String ResolveText(String e);

}
