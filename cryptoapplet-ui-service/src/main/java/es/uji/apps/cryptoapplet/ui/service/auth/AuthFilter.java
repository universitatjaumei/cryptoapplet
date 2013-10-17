package es.uji.apps.cryptoapplet.ui.service.auth;

import es.uji.apps.cryptoapplet.ui.auth.TokenGenerator;

import javax.servlet.*;
import javax.ws.rs.Path;
import java.io.IOException;

@Path("auth")
public class AuthFilter implements Filter
{
    @Override
    public void init(FilterConfig filterConfig) throws ServletException
    {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException
    {
        String appName = servletRequest.getParameter("appName");
        String timestamp = servletRequest.getParameter("timestamp");
        String signature = servletRequest.getParameter("signature");

        String tokenData = String.format("%s:%s", appName, timestamp);

        TokenGenerator tokenGenerator = new TokenGenerator();
        boolean tokenValid = tokenGenerator.verifyToken(tokenData, signature);

        if (!tokenValid)
        {
            throw new RuntimeException("Invalid token");
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy()
    {
    }
}