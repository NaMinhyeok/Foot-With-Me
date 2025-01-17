package team4.footwithme.resevation.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Slice;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import team4.footwithme.chat.service.event.ReservationDeletedEvent;
import team4.footwithme.chat.service.event.ReservationMembersJoinEvent;
import team4.footwithme.chat.service.event.ReservationPublishedEvent;
import team4.footwithme.global.exception.ExceptionMessage;
import team4.footwithme.global.repository.CustomGlobalRepository;
import team4.footwithme.member.domain.Gender;
import team4.footwithme.member.domain.Member;
import team4.footwithme.member.repository.MemberRepository;
import team4.footwithme.resevation.domain.*;
import team4.footwithme.resevation.repository.GameRepository;
import team4.footwithme.resevation.repository.MercenaryRepository;
import team4.footwithme.resevation.repository.ParticipantRepository;
import team4.footwithme.resevation.repository.ReservationRepository;
import team4.footwithme.resevation.service.request.ReservationUpdateServiceRequest;
import team4.footwithme.resevation.service.response.ReservationInfoDetailsResponse;
import team4.footwithme.resevation.service.response.ReservationInfoResponse;
import team4.footwithme.resevation.service.response.ReservationsResponse;
import team4.footwithme.stadium.domain.Court;
import team4.footwithme.stadium.repository.CourtRepository;
import team4.footwithme.team.domain.Team;
import team4.footwithme.team.repository.TeamRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class ReservationServiceImpl implements ReservationService {

    private final ReservationRepository reservationRepository;
    private final CourtRepository courtRepository;
    private final MemberRepository memberRepository;
    private final TeamRepository teamRepository;
    private final ParticipantRepository participantRepository;
    private final MercenaryRepository mercenaryRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final GameRepository gameRepository;

    @Transactional(readOnly = true)
    public Slice<ReservationsResponse> findReadyReservations(Long reservationId, Integer page) {
        PageRequest pageRequest = PageRequest.of(page, 10, Sort.by(Sort.Direction.ASC, "createdAt"));
        Reservation reservation = (Reservation) findEntityByIdOrThrowException(reservationRepository, reservationId, ExceptionMessage.RESERVATION_NOT_FOUND);

        if (reservation.getReservationStatus() != ReservationStatus.READY) {
            throw new IllegalArgumentException(ExceptionMessage.RESERVATION_STATUS_NOT_READY.getText());
        }

        return reservationRepository.findByMatchDateAndCourtAndReservationStatus(
                reservationId, reservation.getMatchDate(), reservation.getCourt(), ReservationStatus.READY, pageRequest)
            .map(ReservationsResponse::from);
    }

    @Transactional
    @Override
    public void createReservation(Long memberId, Long courtId, Long teamId, LocalDateTime matchDate, List<Long> memberIds) {
        Court court = courtRepository.findActiveById(courtId)
            .orElseThrow(() -> new IllegalArgumentException("해당하는 구장이 없습니다."));
        Member member = memberRepository.findActiveById(memberId)
            .orElseThrow(() -> new IllegalArgumentException("해당하는 회원이 없습니다."));
        Team team = teamRepository.findById(teamId)
            .orElseThrow(() -> new IllegalArgumentException("해당하는 팀이 없습니다."));

        List<Member> participantMembers = memberRepository.findAllById(memberIds);

        Reservation reservation = createReservationOf(court, member, team, matchDate, participantMembers);
        Reservation savedReservation = reservationRepository.save(reservation);

        List<Participant> participants = createParticipantsOf(savedReservation, participantMembers);
        participantRepository.saveAll(participants);

        if (memberIds.size() < 6) {
            Mercenary mercenary = Mercenary.createDefault(reservation);
            mercenaryRepository.save(mercenary);
        }

        publishChatEventsOf(savedReservation, participants);
    }

    private Reservation createReservationOf(Court court, Member member, Team team, LocalDateTime matchDate, List<Member> participantMembers) {
        ParticipantGender gender = classifyGenderBy(participantMembers);

        if (participantMembers.size() >= 6) {
            return Reservation.createReadyReservation(court, member, team, gender, matchDate);
        }
        return Reservation.createRecruitReservation(court, member, team, gender, matchDate);
    }

    private ParticipantGender classifyGenderBy(List<Member> participantMembers) {
        if (participantMembers.stream().allMatch(m -> m.getGender() == Gender.MALE)) {
            return ParticipantGender.MALE;
        }
        if (participantMembers.stream().allMatch(m -> m.getGender() == Gender.FEMALE)) {
            return ParticipantGender.FEMALE;
        }
        return ParticipantGender.MIXED;
    }

    private List<Participant> createParticipantsOf(Reservation reservation, List<Member> participantMembers) {
        return participantMembers.stream()
            .map(participantMember -> Participant.create(reservation, participantMember, ParticipantRole.MEMBER))
            .toList();
    }

    private void publishChatEventsOf(Reservation reservation, List<Participant> participants) {
        eventPublisher.publishEvent(new ReservationPublishedEvent("예약 채팅방", reservation.getReservationId()));
        eventPublisher.publishEvent(new ReservationMembersJoinEvent(participants, reservation.getReservationId()));
    }

    @Override
    @Transactional(readOnly = true)
    public List<ReservationInfoResponse> getTeamReservationInfo(Long teamId) {

        List<Reservation> reservations = findByTeamTeamIdOrThrowException(teamId);

        List<ReservationInfoResponse> list = reservations.stream()
            .map(ReservationInfoResponse::from)
            .collect(Collectors.toList());

        return list;
    }

    @Override
    @Transactional(readOnly = true)
    public ReservationInfoDetailsResponse getTeamReservationInfoDetails(Long reservationId) {
        Reservation reservation = reservationRepository.findById(reservationId)
            .orElseThrow(() -> new IllegalArgumentException("해당 예약을 찾을 수 없습니다."));

        List<Participant> participants = participantRepository.findParticipantsByReservationId(reservationId);

        //상대팀 조회
        Reservation matchedTeam = gameRepository.findFirstTeamReservationBySecondTeamReservationId(reservationId)
            .orElse(null);
        //상대팀 이름 --> 없으면 null
        String matchTeamName;
        if (matchedTeam == null) {
            matchTeamName = null;
        } else {
            matchTeamName = matchedTeam.getTeam().getName();
        }

        return ReservationInfoDetailsResponse.of(reservation, participants, matchTeamName);
    }

    private <T> T findEntityByIdOrThrowException(CustomGlobalRepository<T> repository, Long id, ExceptionMessage exceptionMessage) {
        return repository.findActiveById(id)
            .orElseThrow(() -> {
                log.warn(">>>> {} : {} <<<<", id, exceptionMessage);
                return new IllegalArgumentException(exceptionMessage.getText());
            });
    }

    public List<Reservation> findByTeamTeamIdOrThrowException(Long teamId) {
        List<Reservation> result = reservationRepository.findByTeamTeamId(teamId);
        if (result.isEmpty()) {
            throw new IllegalArgumentException("해당 팀이 존재하지 않습니다.");
        }
        return result;
    }

    @Transactional
    @Override
    public Long deleteReservation(Long reservationId, Member member) {
        Reservation reservation = reservationRepository.findById(reservationId)
            .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 예약입니다."));

        if (reservation.getReservationStatus() != ReservationStatus.RECRUITING) {
            throw new IllegalArgumentException("취소할 수 없는 예약 입니다.");
        }

        if (!reservation.getMember().getMemberId().equals(member.getMemberId())) {
            throw new IllegalArgumentException("예약한 사람만이 취소할 수 있습니다.");
        }

        deleteGames(reservationId);
        deleteMercenaries(reservationId);
        deleteParticipants(reservationId);

        reservationRepository.delete(reservation);
        eventPublisher.publishEvent(new ReservationDeletedEvent(reservationId));

        return reservationId;
    }

    @Transactional
    public void deleteGames(Long reservationId) {
        List<Game> games = gameRepository.findAllByReservationId(reservationId);
        gameRepository.deleteAllInBatch(games);
    }

    @Transactional
    public void deleteMercenaries(Long reservationId) {
        List<Mercenary> mercenaries = mercenaryRepository.findAllMercenaryByReservationId(reservationId);
        mercenaryRepository.deleteAllInBatch(mercenaries);
    }

    @Transactional
    public void deleteParticipants(Long reservationId) {
        List<Participant> participants = participantRepository.findAllByReservationId(reservationId);
        participantRepository.deleteAllInBatch(participants);
    }

    /**
     * 매칭 예약 상태 변경 API
     * 예약 방장만 상태 변경 가능
     */
    @Transactional
    @Override
    public ReservationInfoResponse changeStatus(ReservationUpdateServiceRequest request, Member member) {
        Reservation reservation = reservationRepository.findById(request.reservationId())
            .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 예약입니다."));

        reservation.checkReservationOwner(member.getMemberId());

        reservation.updateStatus(request.status());

        return ReservationInfoResponse.from(reservation);
    }


}