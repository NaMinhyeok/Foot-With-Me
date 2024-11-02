package team4.footwithme.global.exception.filter;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import team4.footwithme.global.util.ErrorResponseUtil;

import java.io.IOException;

public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        ErrorResponseUtil.sendErrorResponse(response, "요청 혹은 인증 정보에 오류가 있습니다.", HttpServletResponse.SC_UNAUTHORIZED, HttpStatus.UNAUTHORIZED);
    }
}
