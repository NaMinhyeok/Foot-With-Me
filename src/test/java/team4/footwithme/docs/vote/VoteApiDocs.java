package team4.footwithme.docs.vote;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.restdocs.payload.JsonFieldType;
import team4.footwithme.docs.RestDocsSupport;
import team4.footwithme.vote.api.VoteApi;
import team4.footwithme.vote.api.request.StadiumChoices;
import team4.footwithme.vote.api.request.VoteStadiumCreateRequest;
import team4.footwithme.vote.service.VoteService;
import team4.footwithme.vote.service.request.VoteStadiumCreateServiceRequest;
import team4.footwithme.vote.service.response.VoteItemResponse;
import team4.footwithme.vote.service.response.VoteResponse;

import java.time.LocalDateTime;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.*;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.PayloadDocumentation.*;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class VoteApiDocs extends RestDocsSupport {

    private final VoteService voteService = mock(VoteService.class);

    @Override
    protected Object initController() {
        return new VoteApi(voteService);
    }


    @DisplayName("구장 투표를 등록하는 API")
    @Test
    void createStadiumVote() throws Exception {
        //given
        LocalDateTime endAt = LocalDateTime.now().plusDays(1);
        StadiumChoices stadiumChoices1 = new StadiumChoices(1L);
        StadiumChoices stadiumChoices2 = new StadiumChoices(2L);
        VoteStadiumCreateRequest request = new VoteStadiumCreateRequest("연말 행사 투표", endAt, List.of(stadiumChoices1, stadiumChoices2));

        given(voteService.createStadiumVote(any(VoteStadiumCreateServiceRequest.class), eq(1L), any(String.class)))
            .willReturn(new VoteResponse(
                1L,
                "연말 행사 투표",
                endAt,
                List.of(new VoteItemResponse(1L, "최강 풋살장", 0L),
                    new VoteItemResponse(2L, "열정 풋살장", 0L)
                )
            ));

        mockMvc.perform(post("/api/v1/votes/stadiums/{teamId}", 1L)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andDo(document("vote-stadium-create",
                preprocessRequest(prettyPrint()),
                preprocessResponse(prettyPrint()),
                requestFields(
                    fieldWithPath("title").description("투표 제목"),
                    fieldWithPath("endAt").description("투표 종료 시간"),
                    fieldWithPath("choices").description("투표 선택지 목록"),
                    fieldWithPath("choices[].stadiumId").description("구장 ID")
                ),
                pathParameters(
                    parameterWithName("teamId").description("팀 ID")
                ),
                responseFields(
                    fieldWithPath("code").type(JsonFieldType.NUMBER)
                        .description("코드"),
                    fieldWithPath("status").type(JsonFieldType.STRING)
                        .description("상태"),
                    fieldWithPath("message").type(JsonFieldType.STRING)
                        .description("메시지"),
                    fieldWithPath("data").type(JsonFieldType.OBJECT)
                        .description("응답 데이터"),
                    fieldWithPath("data.voteId").type(JsonFieldType.NUMBER)
                        .description("투표 ID"),
                    fieldWithPath("data.title").type(JsonFieldType.STRING)
                        .description("투표 제목"),
                    fieldWithPath("data.endAt").type(JsonFieldType.ARRAY)
                        .description("투표 종료 시간"),
                    fieldWithPath("data.choices").type(JsonFieldType.ARRAY)
                        .description("투표 선택지 목록"),
                    fieldWithPath("data.choices[].voteItemId").type(JsonFieldType.NUMBER)
                        .description("투표 선택지 ID"),
                    fieldWithPath("data.choices[].content").type(JsonFieldType.STRING)
                        .description("투표 선택지 내용"),
                    fieldWithPath("data.choices[].voteCount").type(JsonFieldType.NUMBER)
                        .description("투표 선택지 투표 수")
                )
            ));
    }

    @DisplayName("구장 투표를 조회하는 API")
    @Test
    void getVoteStadium() throws Exception {
        LocalDateTime endAt = LocalDateTime.now().plusDays(1);
        long voteId = 1L;

        given(voteService.getStadiumVote(voteId))
            .willReturn(new VoteResponse(
                1L,
                "연말 행사 투표",
                endAt,
                List.of(new VoteItemResponse(1L, "최강 풋살장", 5L),
                    new VoteItemResponse(2L, "열정 풋살장", 4L)
                )
            ));

        mockMvc.perform(get("/api/v1/votes/{voteId}",voteId)
            .contentType(MediaType.APPLICATION_JSON))
            .andDo(document("vote-stadium-get",
                preprocessRequest(prettyPrint()),
                preprocessResponse(prettyPrint()),
                pathParameters(
                    parameterWithName("voteId").description("투표 ID")
                ),
                responseFields(
                    fieldWithPath("code").type(JsonFieldType.NUMBER)
                        .description("코드"),
                    fieldWithPath("status").type(JsonFieldType.STRING)
                        .description("상태"),
                    fieldWithPath("message").type(JsonFieldType.STRING)
                        .description("메시지"),
                    fieldWithPath("data").type(JsonFieldType.OBJECT)
                        .description("응답 데이터"),
                    fieldWithPath("data.voteId").type(JsonFieldType.NUMBER)
                        .description("투표 ID"),
                    fieldWithPath("data.title").type(JsonFieldType.STRING)
                        .description("투표 제목"),
                    fieldWithPath("data.endAt").type(JsonFieldType.ARRAY)
                        .description("투표 종료 시간"),
                    fieldWithPath("data.choices").type(JsonFieldType.ARRAY)
                        .description("투표 선택지 목록"),
                    fieldWithPath("data.choices[].voteItemId").type(JsonFieldType.NUMBER)
                        .description("투표 선택지 ID"),
                    fieldWithPath("data.choices[].content").type(JsonFieldType.STRING)
                        .description("투표 선택지 내용"),
                    fieldWithPath("data.choices[].voteCount").type(JsonFieldType.NUMBER)
                        .description("투표 선택지 투표 수")
                )
            ));
    }

}
