package team4.footwithme.member.oauth2.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import team4.footwithme.global.util.ErrorResponseUtil;

import java.io.IOException;

@Component
public class CustomOAuth2LoginFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        ErrorResponseUtil.sendErrorResponse(response, "인증 실패", HttpServletResponse.SC_UNAUTHORIZED, HttpStatus.UNAUTHORIZED);
    }
}
