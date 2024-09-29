package team4.footwithme.member.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import team4.footwithme.global.domain.BaseEntity;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
//@SQLDelete(sql = "UPDATE member SET is_deleted = 'TRUE' WHERE member_id = ?")
@Entity
public class Member extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long memberId;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String phoneNumber;

    @Embedded
    private LoginType loginType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Gender gender;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private MemberRole memberRole;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TermsAgreed termsAgreed;

    @Builder
    private Member(String email, String password, String name, String phoneNumber, LoginType loginType, Gender gender, MemberRole memberRole, TermsAgreed termsAgreed) {
        this.email = email;
        this.password = password;
        this.name = name;
        this.phoneNumber = phoneNumber;
        this.loginType = loginType;
        this.gender = gender;
        this.memberRole = memberRole;
        this.termsAgreed = termsAgreed;
    }

    public static Member create(String email, String password, String name, String phoneNumber, LoginProvider loginProvider, String snsId, Gender gender, MemberRole memberRole, TermsAgreed termsAgreed) {
        return Member.builder()
            .email(email)
            .password(password)
            .name(name)
            .phoneNumber(phoneNumber)
            .loginType(LoginType.builder()
                .loginProvider(loginProvider)
                .snsId(snsId)
                .build())
            .gender(gender)
            .memberRole(memberRole)
            .termsAgreed(termsAgreed)
            .build();
    }
}
