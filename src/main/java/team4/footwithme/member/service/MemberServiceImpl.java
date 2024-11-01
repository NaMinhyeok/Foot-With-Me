package team4.footwithme.member.service;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import team4.footwithme.member.domain.Member;
import team4.footwithme.member.jwt.JwtTokenFilter;
import team4.footwithme.member.jwt.JwtTokenUtil;
import team4.footwithme.member.jwt.response.TokenResponse;
import team4.footwithme.member.repository.MemberRepository;
import team4.footwithme.member.service.request.JoinServiceRequest;
import team4.footwithme.member.service.request.LoginServiceRequest;
import team4.footwithme.member.service.request.UpdatePasswordServiceRequest;
import team4.footwithme.member.service.request.UpdateServiceRequest;
import team4.footwithme.member.service.response.LoginResponse;
import team4.footwithme.member.service.response.MemberResponse;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class MemberServiceImpl implements MemberService {

    private final MemberRepository memberRepository;
    private final JwtTokenUtil jwtTokenUtil;
    private final RedisTemplate redisTemplate;
    private final BCryptPasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public MemberResponse join(JoinServiceRequest serviceRequest) {
        checkDuplicateEmail(serviceRequest.email());
        Member member = serviceRequest.toEntity();

        if (!member.isOAuthMember()) {
            member.encodePassword(passwordEncoder);
        }

        memberRepository.save(member);

        return MemberResponse.from(member);

    }

    @Override
    @Transactional
    public LoginResponse login(LoginServiceRequest serviceRequest) {
        Member member = findMemberByEmailElseThrow(serviceRequest.email());
        checkPasswordMatch(serviceRequest.password(), member.getPassword());

        TokenResponse tokenResponse = jwtTokenUtil.createToken(member.getEmail());
        setRedis(member.getEmail(), tokenResponse.refreshToken(), tokenResponse.refreshTokenExpirationTime(), TimeUnit.MICROSECONDS);

        return LoginResponse.from(tokenResponse);
    }

    @Override
    @Transactional
    public String logout(HttpServletRequest request) {
        String accessToken = jwtTokenUtil.resolveToken(request);
        String email = jwtTokenUtil.getEmailFromToken(accessToken);

        jwtTokenUtil.tokenValidation(accessToken);

        if (redisTemplate.opsForValue().get(email) != null) {
            redisTemplate.delete(email);
        }

        long expiration = jwtTokenUtil.getExpiration(accessToken);
        setRedis(accessToken, "logout", expiration, TimeUnit.MICROSECONDS);

        return "Success Logout";
    }

    @Override
    public TokenResponse reissue(HttpServletRequest request, String refreshToken) {
        if (refreshToken.isEmpty()) {
            refreshToken = JwtTokenFilter.getRefreshTokenByRequest(request); // 헤더에 없을 경우 쿠키에서 꺼내 씀
        }

        jwtTokenUtil.tokenValidation(refreshToken);
        return convertToTokenResponseFrom(refreshToken);
    }

    @Override
    @Transactional
    public MemberResponse update(Member member, UpdateServiceRequest request) {
        member.update(request.name(), request.phoneNumber(), request.gender());
        memberRepository.save(member);

        return MemberResponse.from(member);
    }

    @Override
    @Transactional
    public String updatePassword(Member member, UpdatePasswordServiceRequest serviceRequest) {
        checkPasswordMatch(serviceRequest.prePassword(), member.getPassword());
        member.changePassword(passwordEncoder.encode(serviceRequest.newPassword()));
        memberRepository.save(member);

        return "Success Change Password";
    }

    private void setRedis(String key, String value, Long expirationTime, TimeUnit timeUnit){
        redisTemplate.opsForValue().set(key, value, expirationTime, timeUnit);
    }

    private Member findMemberByEmailElseThrow(String email){
        return memberRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 사용자 입니다."));
    }

    private void checkPasswordMatch(String password, String passwordConfirm){
        if (!passwordEncoder.matches(password, passwordConfirm)) {
            throw new IllegalArgumentException("패스워드가 일치하지 않습니다.");
        }
    }

    private void checkDuplicateEmail(String email){
        if (memberRepository.existByEmail(email))
            throw new IllegalArgumentException("이미 존재하는 이메일 입니다.");
    }

    private TokenResponse convertToTokenResponseFrom(String refreshToken) {
        return TokenResponse.of(
                jwtTokenUtil.reCreateAccessToken(refreshToken),
                refreshToken,
                jwtTokenUtil.getExpiration(refreshToken)
        );
    }
}
