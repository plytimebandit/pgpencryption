package org.plytimebandit.tools.pgpencryption.sys;

import org.apache.logging.log4j.Logger;

public class ProcessLogger {

    private static final int NUMBER_OF_STEPS_TO_LOG = 10;

    private final Logger logger;
    private final int totalSteps;

    private int stepCounter = 0;
    private int loggedStepsCounter = 0;
    private int logInterval;

    public ProcessLogger(Logger logger, int totalSteps) {
        this.logger = logger;
        this.totalSteps = totalSteps;

        this.logInterval = totalSteps / NUMBER_OF_STEPS_TO_LOG + 1;
    }

    public void logNextStep(String message) {
        stepCounter++;
        if (stepCounter % logInterval == 0 || stepCounter == totalSteps) {
            logger.info(message + " {} %", ++loggedStepsCounter * (100 / NUMBER_OF_STEPS_TO_LOG));
        }
    }

}
