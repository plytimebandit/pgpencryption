package org.plytimebandit.tools.pgpencryption.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.logging.log4j.Logger;
import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

public class ProcessLoggerTest {

    @Test
    public void testTotalSteps0() throws Exception {
        List<Integer> logValues = Collections.emptyList();
        Logger loggerMock = getMockedLogger(logValues);

        ProcessLogger processLogger = new ProcessLogger(loggerMock, "msg", 0);
        processLogger.logNextStep();

        Mockito.verify(loggerMock, Mockito.never()).info(ArgumentMatchers.anyString(), ArgumentMatchers.any(Number.class));
    }

    @Test
    public void testTotalSteps1() throws Exception {
        List<Integer> logValues = Collections.singletonList(100);
        Logger loggerMock = getMockedLogger(logValues);

        ProcessLogger processLogger = new ProcessLogger(loggerMock, "msg", 1);
        processLogger.logNextStep();

        Mockito.verify(loggerMock).info(ArgumentMatchers.anyString(), ArgumentMatchers.any(Number.class));
    }

    @Test
    public void testTotalSteps10() throws Exception {
        List<Integer> logValues = Arrays.asList(10, 20, 30, 40, 50, 60, 70, 80, 90, 100);
        Logger loggerMock = getMockedLogger(logValues);

        ProcessLogger processLogger = new ProcessLogger(loggerMock, "msg", 10);
        for (int i = 0; i < 10; i++) {
            processLogger.logNextStep();
        }

        Mockito.verify(loggerMock, Mockito.times(10)).info(ArgumentMatchers.anyString(), ArgumentMatchers.any(Number.class));
    }

    @Test
    public void testTotalSteps5() throws Exception {
        List<Integer> logValues = Arrays.asList(20, 40, 60, 80, 100);
        Logger loggerMock = getMockedLogger(logValues);

        ProcessLogger processLogger = new ProcessLogger(loggerMock, "msg", 5);
        for (int i = 0; i < 5; i++) {
            processLogger.logNextStep();
        }

        Mockito.verify(loggerMock, Mockito.times(5)).info(ArgumentMatchers.anyString(), ArgumentMatchers.any(Number.class));
    }

    @Test
    public void testTotalSteps100() throws Exception {
        List<Integer> logValues = Arrays.asList(10, 20, 30, 40, 50, 60, 70, 80, 90, 100);
        Logger loggerMock = getMockedLogger(logValues);

        ProcessLogger processLogger = new ProcessLogger(loggerMock, "msg", 100);
        for (int i = 0; i < 100; i++) {
            processLogger.logNextStep();
        }

        Mockito.verify(loggerMock, Mockito.times(10)).info(ArgumentMatchers.anyString(), ArgumentMatchers.any(Number.class));
    }

    @Test
    public void testTotalSteps444() throws Exception {
        List<Integer> logValues = Arrays.asList(10, 20, 30, 40, 50, 60, 70, 80, 90, 100);
        Logger loggerMock = getMockedLogger(logValues);

        ProcessLogger processLogger = new ProcessLogger(loggerMock, "msg", 444);
        for (int i = 0; i < 444; i++) {
            processLogger.logNextStep();
        }

        Mockito.verify(loggerMock, Mockito.times(10)).info(ArgumentMatchers.anyString(), ArgumentMatchers.any(Number.class));
    }

    @Test
    public void testTotalSteps444WithNumberOfStepsToLog5() throws Exception {
        List<Integer> logValues = Arrays.asList(20, 40, 60, 80, 100);
        Logger loggerMock = getMockedLogger(logValues);

        ProcessLogger processLogger = new ProcessLogger(loggerMock, "msg", 444).withNumberOfStepsToLog(5);
        for (int i = 0; i < 444; i++) {
            processLogger.logNextStep();
        }

        Mockito.verify(loggerMock, Mockito.times(5)).info(ArgumentMatchers.anyString(), ArgumentMatchers.any(Number.class));
    }

    @Test
    public void testTotalSteps444WithNumberOfStepsToLog3() throws Exception {
        List<Integer> logValues = Arrays.asList(33, 66, 99);
        Logger loggerMock = getMockedLogger(logValues);

        ProcessLogger processLogger = new ProcessLogger(loggerMock, "msg", 444).withNumberOfStepsToLog(3);
        for (int i = 0; i < 444; i++) {
            processLogger.logNextStep();
        }

        Mockito.verify(loggerMock, Mockito.times(3)).info(ArgumentMatchers.anyString(), ArgumentMatchers.any(Number.class));
    }

    @Test
    public void testTotalSteps444WithNumberOfStepsToLog1() throws Exception {
        List<Integer> logValues = Collections.singletonList(100);
        Logger loggerMock = getMockedLogger(logValues);

        ProcessLogger processLogger = new ProcessLogger(loggerMock, "msg", 444).withNumberOfStepsToLog(1);
        for (int i = 0; i < 444; i++) {
            processLogger.logNextStep();
        }

        Mockito.verify(loggerMock).info(ArgumentMatchers.anyString(), ArgumentMatchers.any(Number.class));
    }

    @Test
    public void testTotalSteps5WithNumberOfStepsToLog10() throws Exception {
        List<Integer> logValues = Arrays.asList(10, 20, 30, 40, 50, 60, 70, 80, 90, 100);
        Logger loggerMock = getMockedLogger(logValues);

        ProcessLogger processLogger = new ProcessLogger(loggerMock, "msg", 10);
        for (int i = 0; i < 5; i++) {
            processLogger.logNextStep();
        }

        Mockito.verify(loggerMock, Mockito.times(5)).info(ArgumentMatchers.anyString(), ArgumentMatchers.any(Number.class));
    }

    private <T> Logger getMockedLogger(List<T> logValues) {
        ArrayList<T> logValuesAsArrayList = new ArrayList<>(logValues);
        Logger loggerMock = Mockito.mock(Logger.class);
        Mockito.doAnswer(invocationOnMock -> {

            if (invocationOnMock.getArguments().length == 0) {
                T remove = logValuesAsArrayList.remove(0);
                System.out.println("Has: NULL, Expected: " + remove);
                Assertions.assertThat(remove).isNull();

            } else {
                Object argument = invocationOnMock.getArgument(1);
                if (logValuesAsArrayList.isEmpty()) {
                    System.out.println("Has: " + argument + ", Expected: FINISHED LOG");
                    Assertions.assertThat(invocationOnMock.getArguments()).isEmpty();
                } else {
                    T remove = logValuesAsArrayList.remove(0);
                    System.out.println("Has: " + argument + ", Expected: " + remove);
                    Assertions.assertThat(argument).isEqualTo(remove);
                }
            }
            return "";

        }).when(loggerMock).info(ArgumentMatchers.anyString(), ArgumentMatchers.any(Number.class));
        return loggerMock;
    }

}