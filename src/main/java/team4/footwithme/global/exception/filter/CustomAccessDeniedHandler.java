package team4.footwithme.global.exception.filter;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import team4.footwithme.global.util.ErrorResponseUtil;

import java.io.IOException;

public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        ErrorResponseUtil.sendErrorResponse(response, "권한이 업습니다.", HttpServletResponse.SC_FORBIDDEN, HttpStatus.FORBIDDEN);
    }
}
