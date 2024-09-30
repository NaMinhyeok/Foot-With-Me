package team4.footwithme.vote.repository;

import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.RequiredArgsConstructor;
import team4.footwithme.vote.domain.Choice;
import team4.footwithme.vote.domain.QChoice;

import java.util.List;

import static team4.footwithme.vote.domain.QChoice.*;
import static team4.footwithme.vote.domain.QVote.vote;
import static team4.footwithme.vote.domain.QVoteItem.voteItem;

@RequiredArgsConstructor
public class CustomChoiceRepositoryImpl implements CustomChoiceRepository {

    private final JPAQueryFactory queryFactory;

    @Override
    public Long countByVoteItemId(Long voteItemId) {
        return queryFactory.select(choice.count())
            .from(choice)
            .where(choice.voteItemId.eq(voteItemId))
            .fetchOne();
    }

    @Override
    public List<Choice> findByMemberIdAndVoteId(Long memberId, Long voteId) {
        return queryFactory.select(choice)
            .from(choice)
            .join(voteItem).on(choice.voteItemId.eq(voteItem.voteItemId))
            .join(voteItem.vote, vote)
            .where(choice.memberId.eq(memberId)
                .and(vote.voteId.eq(voteId)))
            .fetch();
    }
}