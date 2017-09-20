package org.plytimebandit.tools.pgpencryption.sys;

import org.apache.logging.log4j.Logger;

public class ProcessLogger {

    private final Logger logger;
    private final int totalSteps;

    private int numberOfStepsToLog = 10;
    private int stepCounter = 0;
    private int loggedStepsCounter = 0;
    private int logInterval;

    public ProcessLogger(Logger logger, int totalSteps) {
        this.logger = logger;
        this.totalSteps = totalSteps;

        if (totalSteps <= numberOfStepsToLog) {
            this.logInterval = 1;
            numberOfStepsToLog = totalSteps;
        } else {
            this.logInterval = totalSteps / numberOfStepsToLog + 1;
        }
    }

    public void logNextStep(String message) {
        stepCounter++;
        if (stepCounter % logInterval == 0 || stepCounter == totalSteps) {
            logger.info(message + " {} %", ++loggedStepsCounter * (100 / numberOfStepsToLog));
        }
    }

}
