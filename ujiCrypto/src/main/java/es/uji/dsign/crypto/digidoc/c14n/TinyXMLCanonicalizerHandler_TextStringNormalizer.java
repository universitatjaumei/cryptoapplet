package es.uji.dsign.crypto.digidoc.c14n;

import es.uji.dsign.crypto.digidoc.c14n.EntityParser_Entity;
import es.uji.dsign.crypto.digidoc.c14n.EntityParser_Handler;
import es.uji.dsign.crypto.digidoc.c14n.TinyXMLCanonicalizerHandler_TextStringNormalizer_EntityHelper;
import es.uji.dsign.crypto.digidoc.c14n.common.Convert;
import es.uji.dsign.crypto.digidoc.c14n.common.Helper;
import es.uji.dsign.crypto.digidoc.c14n.common.StringImplementation;

class TinyXMLCanonicalizerHandler_TextStringNormalizer implements EntityParser_Handler
{
    public boolean IsAttribute;


    public TinyXMLCanonicalizerHandler_TextStringNormalizer()
    {
    }


    public String ResolveEntity(EntityParser_Entity e)
    {

        if (e.get_IsNumeric())
        {

            if (!this.IsAttribute)
            {

                if ((e.get_IntegerValue() == 10))
                {
                    return "\n";
                }

            }


            if ((e.get_IntegerValue() == 32))
            {
                return " ";
            }


            if (Helper.IsVisibleChar(e.get_IntegerValue()))
            {
                return Convert.ToString(((char)e.get_IntegerValue()));
            }

            return "&#x"+ e.get_HexValue()+ ";";
        }


        if (this.IsAttribute)
        {

            if (e.get_Text().equals("apos"))
            {
                return "\'";
            }

        }

        return e.get_OriginalString();
    }

    public String ResolveText(String e)
    {
        TinyXMLCanonicalizerHandler_TextStringNormalizer_EntityHelper h;

        h = new TinyXMLCanonicalizerHandler_TextStringNormalizer_EntityHelper(e);
        h.set_Item("&", "&amp;");
        h.set_Item("\r", "&#xD;");

        if (this.IsAttribute)
        {
            h.set_Item("\"", "&quot;");
            h.set_Item("\t", "&#x9;");
            h.set_Item("\n", "&#xA;");
        }
        else
        {
            h.set_Item("<", "&lt;");
            h.set_Item(">", "&gt;");
        }

        return h.Text;
    }

    public static String StaticResolveTextCData(String e)
    {
        TinyXMLCanonicalizerHandler_TextStringNormalizer_EntityHelper h;

        h = new TinyXMLCanonicalizerHandler_TextStringNormalizer_EntityHelper(e);
        h.set_Item("&", "&amp;");
        h.set_Item("<", "&lt;");
        h.set_Item(">", "&gt;");
        h.set_Item("\r", "&#xD;");
        return h.Text;
    }

}
