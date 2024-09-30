package team4.footwithme.resevation.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import team4.footwithme.resevation.domain.Game;

@Repository
public interface GameRepository extends JpaRepository<Game, Long> {

}