package es.uji.dsign.crypto.digidoc.c14n;

import es.uji.dsign.crypto.digidoc.c14n.TinyXMLParser_Fragment;
import es.uji.dsign.crypto.digidoc.c14n.TinyXMLParser_Node;

public final class TinyXMLParser_TextNode extends TinyXMLParser_Node
{
    public TinyXMLParser_Fragment ValueFragment;


    public TinyXMLParser_TextNode()
    {
        super();
    }


    public void ToConsole()
    {
        this.ValueFragment.ToConsole();
    }

}
