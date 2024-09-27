package team4.footwithme.chat.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import team4.footwithme.chat.domain.ChatMember;
import team4.footwithme.chat.domain.Chatroom;
import team4.footwithme.member.domain.Member;

@Repository
public interface ChatMemberRepository extends JpaRepository<ChatMember, Long> {
    void deleteByMemberAndChatRoom(Member member, Chatroom chatroom);

    void deleteByChatRoom(Chatroom chatroom);

    // TODO 성능상 이슈 존재 QueryDSL 사용해서 Limit 걸어 사용하기
    @Query("select COUNT(c.ChatMemberId) > 0 from ChatMember c where c.isDeleted='false' and c.member = :member and c.chatRoom = :chatroom")
    boolean existsByMemberAndChatRoom(@Param("member") Member member, @Param("chatroom") Chatroom chatroom);


}
