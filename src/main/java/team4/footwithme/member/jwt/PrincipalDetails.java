package team4.footwithme.member.jwt;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import team4.footwithme.member.domain.Member;
import team4.footwithme.member.domain.MemberRole;

import java.util.Collection;

public class PrincipalDetails implements UserDetails {

    @Getter
    private Member member;
    private Collection<? extends GrantedAuthority> authorities;

    public PrincipalDetails(Member member, Collection<? extends GrantedAuthority> authorities) {
        this.member = member;
        this.authorities = authorities;
    }

    public MemberRole getMemberRole() {
        return member.getMemberRole();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return member.getPassword();
    }

    @Override
    public String getUsername() {
        return member.getEmail();
    }


}
