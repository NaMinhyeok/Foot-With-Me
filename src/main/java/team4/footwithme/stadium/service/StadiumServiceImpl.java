package team4.footwithme.stadium.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.locationtech.jts.geom.Point;
import org.springframework.stereotype.Service;
import team4.footwithme.global.util.PositionUtil;
import team4.footwithme.stadium.exception.StadiumExceptionMessage;
import team4.footwithme.stadium.service.request.StadiumSearchByLocationServiceRequest;
import team4.footwithme.stadium.service.response.StadiumDetailResponse;
import team4.footwithme.stadium.service.response.StadiumsResponse;
import team4.footwithme.stadium.domain.Stadium;
import team4.footwithme.stadium.repository.StadiumRepository;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Service
public class StadiumServiceImpl implements StadiumService {

    private final StadiumRepository stadiumRepository;

    // 구장 목록 조회
    public List<StadiumsResponse> getStadiumList() {
        return stadiumRepository.findAll().stream()
                .map(stadium -> new StadiumsResponse(stadium.getStadiumId(), stadium.getName(), stadium.getAddress()))
                .toList();
    }

    // 구장 상세 정보 조회
    public StadiumDetailResponse getStadiumDetail(Long id) {
        Stadium stadium = findByIdOrThrowException(id);
        Point position = stadium.getPosition();

        return StadiumDetailResponse.of(stadium, position);
    }

    // 이름으로 구장 검색
    public List<StadiumsResponse> getStadiumsByName(String query) {
        List<Stadium> stadiums = stadiumRepository.findByNameContainingIgnoreCase(query);
        return Optional.ofNullable(stadiums)
                .orElse(Collections.emptyList())
                .stream()
                .map(stadium -> StadiumsResponse.of(stadium))
                .collect(Collectors.toList());
    }

    // 주소로 구장 검색
    public List<StadiumsResponse> getStadiumsByAddress(String address) {
        List<Stadium> stadiums = stadiumRepository.findByAddressContainingIgnoreCase(address);
        return Optional.ofNullable(stadiums)
                .orElse(Collections.emptyList())
                .stream()
                .map(stadium -> StadiumsResponse.of(stadium))  // of 메서드 사용
                .collect(Collectors.toList());
    }

    // 위도, 경도의 일정 거리 내의 구장 목록 반환
    public List<StadiumsResponse> getStadiumsWithinDistance(StadiumSearchByLocationServiceRequest request) {
        Point point = PositionUtil.createPoint(request.latitude(), request.longitude());
        String wktPoint = String.format("POINT(%s %s)", point.getY(), point.getX());
        List<Stadium> stadiums = stadiumRepository.findStadiumsByLocation(wktPoint, request.distance());
        return stadiums.stream()
                .map(stadium -> new StadiumsResponse(stadium.getStadiumId(), stadium.getName(), stadium.getAddress()))
                .collect(Collectors.toList());
    }

    // 구장 조회 예외처리
    public Stadium findByIdOrThrowException(long id) {
        return stadiumRepository.findById(id)
                .orElseThrow(() -> {
                    log.warn(">>>> {} : {} <<<<", id, StadiumExceptionMessage.STADIUM_NOT_FOUND);
                    return new IllegalArgumentException(StadiumExceptionMessage.STADIUM_NOT_FOUND.getText());
                });
    }
}
