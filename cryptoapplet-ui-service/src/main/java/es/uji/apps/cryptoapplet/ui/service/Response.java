package es.uji.apps.cryptoapplet.ui.service;

public class Response
{
    private String callback;

    public Response(String callback)
    {
        this.callback = callback;
    }

    public String build(DataObject data)
    {
        String payLoad = callback + "(" + data.toString() + ")";
        int contentLength = payLoad.length();

        StringBuffer response = new StringBuffer();
        response.append("HTTP/1.1 200 OK\r\n");
        response.append("Content-Type: text/javascript; charset=utf-8\r\n");
        response.append("Content-Length: ").append(contentLength).append("\r\n");
        response.append("\r\n");
        response.append(payLoad);

        return response.toString();
    }
}
