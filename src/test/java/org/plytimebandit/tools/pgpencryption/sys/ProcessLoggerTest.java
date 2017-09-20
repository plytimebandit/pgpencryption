package org.plytimebandit.tools.pgpencryption.sys;

import java.util.ArrayList;

import org.apache.logging.log4j.Logger;
import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import com.sun.tools.javac.util.List;

public class ProcessLoggerTest {

    @Test
    public void testTotalSteps10() throws Exception {
        List<Integer> logValues = List.of(10, 20, 30, 40, 50, 60, 70, 80, 90, 100);
        Logger loggerMock = getMockedLogger(logValues);

        ProcessLogger processLogger = new ProcessLogger(loggerMock, 10);
        for (int i = 0; i < 10; i++) {
            processLogger.logNextStep("msg");
        }

        Mockito.verify(loggerMock, Mockito.times(10)).info(ArgumentMatchers.anyString(), ArgumentMatchers.any(Number.class));
    }

    @Test
    public void testTotalSteps5() throws Exception {
        List<Integer> logValues = List.of(20, 40, 60, 80, 100);
        Logger loggerMock = getMockedLogger(logValues);

        ProcessLogger processLogger = new ProcessLogger(loggerMock, 5);
        for (int i = 0; i < 5; i++) {
            processLogger.logNextStep("msg");
        }

        Mockito.verify(loggerMock, Mockito.times(5)).info(ArgumentMatchers.anyString(), ArgumentMatchers.any(Number.class));
    }

    @Test
    public void testTotalSteps100() throws Exception {
        List<Integer> logValues = List.of(10, 20, 30, 40, 50, 60, 70, 80, 90, 100);
        Logger loggerMock = getMockedLogger(logValues);

        ProcessLogger processLogger = new ProcessLogger(loggerMock, 100);
        for (int i = 0; i < 100; i++) {
            processLogger.logNextStep("msg");
        }

        Mockito.verify(loggerMock, Mockito.times(10)).info(ArgumentMatchers.anyString(), ArgumentMatchers.any(Number.class));
    }

    private <T> Logger getMockedLogger(List<T> logValues) {
        ArrayList<T> logValuesAsArrayList = new ArrayList<>(logValues);
        Logger loggerMock = Mockito.mock(Logger.class);
        Mockito.doAnswer(invocationOnMock -> {
            T remove = logValuesAsArrayList.remove(0);
            System.out.println("Has: " + invocationOnMock.getArgument(1) + ", Should be: " + remove);
            Assertions.assertThat((Object) invocationOnMock.getArgument(1)).isEqualTo(remove);
            return "";
        }).when(loggerMock).info(ArgumentMatchers.anyString(), ArgumentMatchers.any(Number.class));
        return loggerMock;
    }

}