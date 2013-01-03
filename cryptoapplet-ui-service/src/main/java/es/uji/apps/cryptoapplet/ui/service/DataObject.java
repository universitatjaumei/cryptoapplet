package es.uji.apps.cryptoapplet.ui.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DataObject
{
    private static String QUOTE = "\"";
    private static String COLON = ":";

    private Map<String, List<Object>> items;

    public DataObject()
    {
        items = new HashMap<String, List<Object>>();
    }

    public void put(String key, Object value)
    {
        List<Object> values = new ArrayList<Object>();

        if (items.get(key) != null)
        {
            values = items.get(key);
        }

        values.add(value);

        items.put(key, values);
    }

    public String toString()
    {
        StringBuffer output = new StringBuffer();

        int length = items.entrySet().size();
        int index = 0;

        output.append("{");

        for (Map.Entry<String, List<Object>> item : items.entrySet())
        {
            output.append(QUOTE);
            output.append(item.getKey());
            output.append(QUOTE).append(COLON);

            if (item.getValue().size() > 1)
            {
                output.append("[");
            }
            else
            {
                output.append(QUOTE);
            }

            int lengthArray = item.getValue().size();
            int indexArray = 0;

            for (Object value : item.getValue())
            {
                if (value instanceof DataObject)
                {
                    output.append(((DataObject) value).toString());
                }
                else
                {
                    output.append(value);
                }

                indexArray++;

                if (indexArray != lengthArray)
                {
                    output.append(",");
                }
            }

            if (item.getValue().size() > 1)
            {
                output.append("]");
            }
            else
            {
                output.append(QUOTE);
            }

            index++;

            if (index != length)
            {
                output.append(",");
            }
        }

        output.append("}");

        return output.toString();
    }
}