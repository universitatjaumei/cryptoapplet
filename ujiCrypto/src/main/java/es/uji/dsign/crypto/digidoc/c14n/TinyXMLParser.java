package es.uji.dsign.crypto.digidoc.c14n;

import java.util.Stack;
import es.uji.dsign.crypto.digidoc.c14n.TinyXMLParser_CData;
import es.uji.dsign.crypto.digidoc.c14n.TinyXMLParser_Comment;
import es.uji.dsign.crypto.digidoc.c14n.TinyXMLParser_Document;
import es.uji.dsign.crypto.digidoc.c14n.TinyXMLParser_Element;
import es.uji.dsign.crypto.digidoc.c14n.TinyXMLParser_Fragment;
import es.uji.dsign.crypto.digidoc.c14n.TinyXMLParser_Handler;
import es.uji.dsign.crypto.digidoc.c14n.TinyXMLParser_NestedElement;
import es.uji.dsign.crypto.digidoc.c14n.TinyXMLParser_Tag;
import es.uji.dsign.crypto.digidoc.c14n.TinyXMLParser_TextNode;
import es.uji.dsign.crypto.digidoc.c14n.common.StringImplementation;

public class TinyXMLParser
{


    public TinyXMLParser()
    {
    }


    public void Fail(TinyXMLParser_Fragment f, String reason) throws java.lang.RuntimeException
    {
        Object[] objectArray0;

        objectArray0 = new Object[]
            {
                "Error line ",
                new Integer(f.get_TextPosition().get_Line()),
                ", column ",
                new Integer(f.get_TextPosition().get_Column()),
                " - ",
                reason
            };
        throw new java.lang.RuntimeException(StringImplementation.Concat(objectArray0));
    }

    public void Parse(TinyXMLParser_Handler h, byte[] data)
    {
        TinyXMLParser_Document doc;
        Stack a;
        TinyXMLParser_Fragment f;
        TinyXMLParser_Element current;
        TinyXMLParser_NestedElement nested;
        TinyXMLParser_Tag def;
        TinyXMLParser_Comment comment;
        TinyXMLParser_Element n;
        TinyXMLParser_CData u;
        TinyXMLParser_TextNode ux;

        try
        {
            doc = new TinyXMLParser_Document();
            doc.ParseHandler = h;
            a = new Stack();
            h.startDocument();
            f = TinyXMLParser_Fragment.Of(data, (int)0);
            f.OwnerDocument = doc;
            f.SplitMarkup();
            current = null;
            while (!(f == null))
            {

                if (f.get_IsMarkup())
                {

                    if (f.get_Item("<!"))
                    {
                        nested = TinyXMLParser_NestedElement.Of(f);

                        if (!(nested == null))
                        {
                            h.nestedElement(nested);
                            f = nested.End.get_Next();
                            continue;
                        }

                    }
                    else
                    {

                        if (f.get_Item("<?"))
                        {
                            def = TinyXMLParser_Tag.Of(f);
                            h.PI(def);
                            f = def.End.get_Next();
                            continue;
                        }


                        if (f.get_Item("<!--"))
                        {
                            comment = new TinyXMLParser_Comment();
                            comment.ValueTag = TinyXMLParser_Tag.Of(f);
                            comment.Parent = current;
                            h.comment(comment);
                            f = comment.ValueTag.End.get_Next();
                            continue;
                        }


                        if (f.get_Item("<"))
                        {
                            n = TinyXMLParser_Element.Of(current, f);
                            f = n.Begin.End.get_Next();
                            h.startElement(n);

                            if (n.Begin.End.get_Item("/>"))
                            {
                                h.endElement(n);
                            }
                            else
                            {

                                if (!(current == null))
                                {
                                    a.push(current);
                                }
                                else
                                {

                                    if (!(doc.DocumentElement == null))
                                    {
                                        this.Fail(f, "document element already defined");
                                    }

                                    doc.DocumentElement = n;
                                }

                                current = n;
                            }

                            continue;
                        }


                        if (f.get_Item("</"))
                        {

                            if ((current == null))
                            {
                                this.Fail(f, "tag is not open");
                            }

                            current.End = TinyXMLParser_Tag.Of(f);

                            if (!current.get_IsValid())
                            {
                                this.Fail(f, "tags dont match : "+ current.get_NameOfBeginTagFragment().get_DataString()+ " vs "+ current.get_NameOfEndTagFragment().get_DataString());
                            }

                            f = current.End.End.get_Next();
                            h.endElement(current);

                            if ((a.size() == 0))
                            {
                                current = null;
                            }
                            else
                            {
                                current = ((TinyXMLParser_Element)a.pop());
                            }

                            continue;
                        }


                        if (f.get_Item("<!["))
                        {
                            u = TinyXMLParser_CData.Of(f);

                            if (!(u == null))
                            {
                                h.cdata(u);
                                f = u.End.get_Next();
                                continue;
                            }

                        }

                    }

                }

                f.JoinNonMarkup();
                ux = new TinyXMLParser_TextNode();
                ux.Parent = current;
                ux.ValueFragment = f;
                h.text(ux);
                f = f.get_Next();
            }
            h.endDocument();
        }
        catch (java.lang.Throwable exc)
        {
        }

    }

}
