package team4.footwithme.vote.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;
import org.springframework.http.MediaType;
import team4.footwithme.ApiTestSupport;
import team4.footwithme.vote.api.request.StadiumChoices;
import team4.footwithme.vote.api.request.VoteCreateRequest;
import team4.footwithme.vote.service.request.VoteCreateServiceRequest;
import team4.footwithme.vote.service.response.VoteItemResponse;
import team4.footwithme.vote.service.response.VoteResponse;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class VoteApiTest extends ApiTestSupport {

    @DisplayName("새로운 구장 투표를 생성한다.")
    @Test
    void createLocateVote() throws Exception {
        //given
        LocalDateTime endAt = LocalDateTime.now().plusDays(1);
        StadiumChoices stadiumChoices1 = new StadiumChoices(1L);
        StadiumChoices stadiumChoices2 = new StadiumChoices(2L);
        VoteCreateRequest request = new VoteCreateRequest("연말 행사 투표", endAt, List.of(stadiumChoices1, stadiumChoices2));


        VoteResponse response = new VoteResponse(
            1L,
            "연말 행사 투표",
            endAt,
            List.of(new VoteItemResponse(1L, "최강 풋살장", 0L),
                new VoteItemResponse(2L, "열정 풋살장", 0L)
            )
        );

        given(voteService.createStadiumVote(any(VoteCreateServiceRequest.class), eq(1L), any(String.class)))
            .willReturn(response);

        mockMvc.perform(post("/api/v1/votes/stadiums/{teamId}", 1L)
                .content(objectMapper.writeValueAsString(request))
                .contentType(MediaType.APPLICATION_JSON))
            .andDo(print())
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.code").value("201"))
            .andExpect(jsonPath("$.status").value("CREATED"))
            .andExpect(jsonPath("$.message").value("CREATED"))
            .andExpect(jsonPath("$.data").isMap())
            .andExpect(jsonPath("$.data.voteId").value(1L))
            .andExpect(jsonPath("$.data.title").value("연말 행사 투표"))
            .andExpect(jsonPath("$.data.endAt").value(endAt.toString()))
            .andExpect(jsonPath("$.data.choices").isArray())
            .andExpect(jsonPath("$.data.choices[0].voteItemId").value(1L))
            .andExpect(jsonPath("$.data.choices[0].content").value("최강 풋살장"))
            .andExpect(jsonPath("$.data.choices[0].voteCount").value(0L))
            .andExpect(jsonPath("$.data.choices[1].voteItemId").value(2L))
            .andExpect(jsonPath("$.data.choices[1].content").value("열정 풋살장"))
            .andExpect(jsonPath("$.data.choices[1].voteCount").value(0L));

    }

    @DisplayName("새로운 구장 투표를 생성 할 때 제목은 필수이다.")
    @Test
    void createLocateVoteWhenTitleIsNotExistThenThrowException() throws Exception {
        //given
        LocalDateTime endAt = LocalDateTime.now().plusDays(1);
        StadiumChoices stadiumChoices1 = new StadiumChoices(1L);
        StadiumChoices stadiumChoices2 = new StadiumChoices(2L);
        VoteCreateRequest request = new VoteCreateRequest(null, endAt, List.of(stadiumChoices1, stadiumChoices2));

        given(voteService.createStadiumVote(any(VoteCreateServiceRequest.class), eq(1L), any(String.class)))
            .willReturn(new VoteResponse(
                1L,
                "연말 행사 투표",
                endAt,
                List.of(new VoteItemResponse(1L, "최강 풋살장", 0L),
                    new VoteItemResponse(2L, "열정 풋살장", 0L)
                )
            ));

        mockMvc.perform(post("/api/v1/votes/stadiums/{teamId}", 1L)
                .content(objectMapper.writeValueAsString(request))
                .contentType(MediaType.APPLICATION_JSON))
            .andDo(print())
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("400"))
            .andExpect(jsonPath("$.status").value("BAD_REQUEST"))
            .andExpect(jsonPath("$.message").value("제목은 필수입니다."))
            .andExpect(jsonPath("$.data").isEmpty());

    }

    @DisplayName("새로운 구장 투표를 생성 할 때 제목은 50자 이하이다.")
    @Test
    void createLocateVoteWhenTitleIsOverLengthThenThrowException() throws Exception {
        //given
        LocalDateTime endAt = LocalDateTime.now().plusDays(1);
        StadiumChoices stadiumChoices1 = new StadiumChoices(1L);
        StadiumChoices stadiumChoices2 = new StadiumChoices(2L);
        VoteCreateRequest request = new VoteCreateRequest("a".repeat(51), endAt, List.of(stadiumChoices1, stadiumChoices2));

        given(voteService.createStadiumVote(any(VoteCreateServiceRequest.class), eq(1L), any(String.class)))
            .willReturn(new VoteResponse(
                1L,
                "연말 행사 투표",
                endAt,
                List.of(new VoteItemResponse(1L, "최강 풋살장", 0L),
                    new VoteItemResponse(2L, "열정 풋살장", 0L)
                )
            ));

        mockMvc.perform(post("/api/v1/votes/stadiums/{teamId}", 1L)
                .content(objectMapper.writeValueAsString(request))
                .contentType(MediaType.APPLICATION_JSON))
            .andDo(print())
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("400"))
            .andExpect(jsonPath("$.status").value("BAD_REQUEST"))
            .andExpect(jsonPath("$.message").value("제목은 50자 이하여야 합니다."))
            .andExpect(jsonPath("$.data").isEmpty());

    }

    @DisplayName("새로운 구장 투표를 생성 할 때 시간은 현재 시간보다 미래의 시간으로 지정해야한다.")
    @Test
    void createLocateVoteWhenEndAtIsBeforeNowThenThrowException() throws Exception {
        //given
        LocalDateTime endAt = LocalDateTime.now().minusDays(1);
        StadiumChoices stadiumChoices1 = new StadiumChoices(1L);
        StadiumChoices stadiumChoices2 = new StadiumChoices(2L);
        VoteCreateRequest request = new VoteCreateRequest("연말 행사 투표", endAt, List.of(stadiumChoices1, stadiumChoices2));

        given(voteService.createStadiumVote(any(VoteCreateServiceRequest.class), eq(1L), any(String.class)))
            .willReturn(new VoteResponse(
                1L,
                "연말 행사 투표",
                endAt,
                List.of(new VoteItemResponse(1L, "최강 풋살장", 0L),
                    new VoteItemResponse(2L, "열정 풋살장", 0L)
                )
            ));

        mockMvc.perform(post("/api/v1/votes/stadiums/{teamId}", 1L)
                .content(objectMapper.writeValueAsString(request))
                .contentType(MediaType.APPLICATION_JSON))
            .andDo(print())
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("400"))
            .andExpect(jsonPath("$.status").value("BAD_REQUEST"))
            .andExpect(jsonPath("$.message").value("투표 종료 시간은 현재 시간보다 미래의 시간으로 지정해야합니다."))
            .andExpect(jsonPath("$.data").isEmpty());

    }

    @DisplayName("새로운 구장 투표를 생성 할 때 구장을 최소 하나 이상 선택해야한다.")
    @Test
    void createLocateVoteWhenStadiumIsNullThenThrowException() throws Exception {
        //given
        LocalDateTime endAt = LocalDateTime.now().plusDays(1);
        VoteCreateRequest request = new VoteCreateRequest("연말 행사 투표", endAt, List.of());

        given(voteService.createStadiumVote(any(VoteCreateServiceRequest.class), eq(1L), any(String.class)))
            .willReturn(new VoteResponse(
                1L,
                "연말 행사 투표",
                endAt,
                List.of(new VoteItemResponse(1L, "최강 풋살장", 0L),
                    new VoteItemResponse(2L, "열정 풋살장", 0L)
                )
            ));

        mockMvc.perform(post("/api/v1/votes/stadiums/{teamId}", 1L)
                .content(objectMapper.writeValueAsString(request))
                .contentType(MediaType.APPLICATION_JSON))
            .andDo(print())
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("400"))
            .andExpect(jsonPath("$.status").value("BAD_REQUEST"))
            .andExpect(jsonPath("$.message").value("구장 선택은 필수입니다."))
            .andExpect(jsonPath("$.data").isEmpty());

    }

    @DisplayName("새로운 구장 투표를 생성 할 때 구장을 중복된 구장을 선택 할 수 없다.")
    @Test
    void createLocateVoteWhenStadiumIsDuplicateThenThrowException() throws Exception {
        //given
        LocalDateTime endAt = LocalDateTime.now().plusDays(1);
        StadiumChoices stadiumChoices1 = new StadiumChoices(1L);
        StadiumChoices stadiumChoices2 = new StadiumChoices(1L);
        VoteCreateRequest request = new VoteCreateRequest("연말 행사 투표", endAt, List.of(stadiumChoices1, stadiumChoices2));

        given(voteService.createStadiumVote(any(VoteCreateServiceRequest.class), eq(1L), any(String.class)))
            .willReturn(new VoteResponse(
                1L,
                "연말 행사 투표",
                endAt,
                List.of(new VoteItemResponse(1L, "최강 풋살장", 0L),
                    new VoteItemResponse(2L, "열정 풋살장", 0L)
                )
            ));

        mockMvc.perform(post("/api/v1/votes/stadiums/{teamId}", 1L)
                .content(objectMapper.writeValueAsString(request))
                .contentType(MediaType.APPLICATION_JSON))
            .andDo(print())
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("400"))
            .andExpect(jsonPath("$.status").value("BAD_REQUEST"))
            .andExpect(jsonPath("$.message").value("중복된 구장은 포함 할 수 없습니다."))
            .andExpect(jsonPath("$.data").isEmpty());

    }

}