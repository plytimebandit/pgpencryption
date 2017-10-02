package org.plytimebandit.tools.pgpencryption.util;

import org.apache.logging.log4j.Logger;

public class ProcessLogger {

    private final Logger logger;
    private final String taskName;
    private final int totalSteps;

    private int numberOfStepsToLog = 10;
    private int stepCounter = 0;
    private int loggedStepsCounter = 0;
    private int logInterval;

    public ProcessLogger(Logger logger, String taskName, int totalSteps) {
        this.logger = logger;
        this.taskName = taskName == null ? "" : taskName;
        this.totalSteps = totalSteps;
        init();
    }

    public ProcessLogger withNumberOfStepsToLog(int steps) {
        numberOfStepsToLog = steps;
        init();
        return this;
    }

    private void init() {
        if (totalSteps <= numberOfStepsToLog) {
            this.logInterval = 1;
            numberOfStepsToLog = totalSteps;
        } else {
            this.logInterval = totalSteps / numberOfStepsToLog + 1;
        }
    }

    public synchronized void logNextStep() {
        if (numberOfStepsToLog == 0) {
            return;
        }

        stepCounter++;
        if (stepCounter % logInterval == 0 || stepCounter == totalSteps) {
            logger.info(taskName + " {} %", ++loggedStepsCounter * (100 / numberOfStepsToLog));
        }
    }

    public void logFinished() {
        logger.info("{} finished.", taskName);
    }
}
