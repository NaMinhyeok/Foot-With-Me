package team4.footwithme.stadium.exception;

import team4.footwithme.global.exception.CustomException;

public class StadiumException extends CustomException {
    public StadiumException(StadiumExceptionMessage message) {super(message.getText());}
}
