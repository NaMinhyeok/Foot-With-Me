package team4.footwithme.global.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import team4.footwithme.global.api.ApiResponse;

import java.io.IOException;

public class ErrorResponseUtil {

    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final String CONTENT_TYPE = "application/json";
    private static final String CHARACTER_ENCODING = "UTF-8";

    public static void sendErrorResponse(HttpServletResponse response, String message, int httpStatusCode, HttpStatus httpStatus) throws IOException {
        response.setStatus(httpStatusCode);
        response.setContentType(CONTENT_TYPE);
        response.setCharacterEncoding(CHARACTER_ENCODING);

        ApiResponse<Object> apiResponse = ApiResponse.of(
                httpStatus,
                message,
                null
        );

        String jsonResponse = objectMapper.writeValueAsString(apiResponse);
        response.getWriter().write(jsonResponse);
    }
}
