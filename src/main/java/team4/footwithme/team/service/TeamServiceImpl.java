package team4.footwithme.team.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import team4.footwithme.member.domain.Gender;
import team4.footwithme.member.domain.Member;
import team4.footwithme.member.repository.MemberRepository;
import team4.footwithme.team.api.request.TeamAddResquest;
import team4.footwithme.team.domain.TeamMember;
import team4.footwithme.team.domain.TeamRate;
import team4.footwithme.team.repository.TeamMemberRepository;
import team4.footwithme.team.repository.TeamRateRepository;
import team4.footwithme.team.service.response.TeamInfoResponse;
import team4.footwithme.team.domain.Team;
import team4.footwithme.team.domain.TotalRecord;
import team4.footwithme.team.repository.TeamRepository;
import team4.footwithme.team.service.response.TeamCreatedResponse;

import java.util.ArrayList;
import java.util.List;

@RequiredArgsConstructor
@Service
public class TeamServiceImpl implements TeamService{

    private final TeamRepository teamRepository;
    private final TeamRateRepository teamRateRepository;
    private final TeamMemberRepository teamMemberRepository;
    private final MemberRepository memberRepository;

    @Override
    @Transactional
    public TeamCreatedResponse createTeam(TeamAddResquest dto) {
        /**
         * # 1.
         * chatRoomId는 일단 가짜 id 넣어놓고,
         * 채팅방 생기면 해당 id 적용
         */
        Long stadiumId = null;
        Long chatRoomId = 100000L;

        //TotalRecord 초반 셋팅: count 0
        TotalRecord totalRecord = TotalRecord.builder()
                .winCount(0)
                .drawCount(0)
                .loseCount(0)
                .build();

        //dto -> entity
        Team entity = Team.create(
                stadiumId,
                chatRoomId,
                dto.name(),
                dto.description(),
                totalRecord.getWinCount(),
                totalRecord.getDrawCount(),
                totalRecord.getLoseCount(),
                dto.location()
        );
        Team createdTeam = teamRepository.save(entity);

        return new TeamCreatedResponse(
                createdTeam.getTeamId(),
                createdTeam.getStadiumId(),
                createdTeam.getChatRoomId(),
                createdTeam.getName(),
                createdTeam.getDescription(),
                createdTeam.getTotalRecord().getWinCount(),
                createdTeam.getTotalRecord().getDrawCount(),
                createdTeam.getTotalRecord().getLoseCount(),
                createdTeam.getLocation()
        );
    }

    // 한 서비스에서 다 들고오는게 좋은건지 각각의 서비스로 운용해야되는건지 모르겠음
    @Override
    public TeamInfoResponse getTeamInfo(Long teamId) {
        //팀 정보
        Team teamEntity = teamRepository.findByTeamId(teamId);

        //팀 평가 ->  List
        List<TeamRate> teamRates = teamRateRepository.findEvaluationsByTeam(teamEntity);
        List<String> evaluations = new ArrayList<>();
        for(TeamRate teamRate : teamRates){
            evaluations.add(teamRate.getEvaluation());
        }
        //팀 멤버 -> List로 불러와서 서비스단에서 성별 count
        List<TeamMember> teamMembers = teamMemberRepository.findTeamMembersByTeam(teamEntity);

        int maleCount = 0;
        int femaleCount = 0;

        for(TeamMember teamMember : teamMembers){
            Member member = teamMember.getMember();
            //성별 count
            if(member.getGender().equals(Gender.MALE))
                maleCount += 1;
            else if(member.getGender().equals(Gender.FEMALE))
                femaleCount += 1;
        }

        return new TeamInfoResponse(
                teamEntity.getName(),
                teamEntity.getDescription(),
                teamEntity.getLocation(),
                teamEntity.getTotalRecord().getWinCount(),
                teamEntity.getTotalRecord().getLoseCount(),
                teamEntity.getTotalRecord().getDrawCount(),
                evaluations,
                maleCount,
                femaleCount
        ) ;
    }
}
