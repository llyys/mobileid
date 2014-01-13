package com.codeborne.security.authenticator;

import com.codeborne.security.AuthenticationException;
import com.codeborne.security.AuthenticationException.Code;
import com.codeborne.security.digidoc.DigiDocServicePortType;
import com.codeborne.security.mobileid.MobileIDSession;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import javax.xml.rpc.holders.IntHolder;
import javax.xml.rpc.holders.StringHolder;
import java.rmi.RemoteException;

import static com.codeborne.security.AuthenticationException.Code.OUTSTANDING_TRANSACTION;
import static com.codeborne.security.AuthenticationException.Code.USER_AUTHENTICATED;
import static java.lang.String.valueOf;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

public class MobileIDAuthenticatorTest {
  MobileIDAuthenticator mid = new MobileIDAuthenticator();

  @Test
  public void startSession() throws RemoteException, AuthenticationException {
    mid.service = mockAuthentication("OK", "Bruce", "Willis", "38105060708", "4567", 123);

    MobileIDSession session = mid.startLogin("+37255667788");
    assertThat(session.firstName, equalTo("Bruce"));
    assertThat(session.lastName, equalTo("Willis"));
    assertThat(session.personalCode, equalTo("38105060708"));
    assertThat(session.sessCode, equalTo(123));
    assertThat(session.challenge, equalTo("4567"));
  }

  @Test(expected = AuthenticationException.class)
  public void throwsExceptionIfError() throws RemoteException, AuthenticationException {
    mid.service = mockError(100);
    mid.startLogin("+37255667788");
  }

  @Test
  public void waitsIfStatusOutstandingTransaction() throws Exception {
    mid.service = mockStatus(OUTSTANDING_TRANSACTION);
    MobileIDSession session = new MobileIDSession(123, "1234", "Bob", "Boboff", "1234567890");
    assertFalse(mid.isLoginComplete(session));

    mid = spy(mid);
    doReturn(true).when(mid).sleep(anyInt());
    try {
      mid.waitForLogin(session);
      fail();
    }
    catch (AuthenticationException e) {
      assertEquals(OUTSTANDING_TRANSACTION, e.getCode());
    }
  }

  @Test
  public void loginCompleteIfStatusUserAuthenticated() throws Exception {
    mid.service = mockStatus(USER_AUTHENTICATED);
    assertTrue(mid.isLoginComplete(new MobileIDSession(123, "1234", "Bob", "Boboff", "1234567890")));
  }

  private DigiDocServicePortType mockStatus(final Code status) throws RemoteException {
    DigiDocServicePortType service = mock(DigiDocServicePortType.class);
    doAnswer(new Answer<Object>() {
      @Override public Object answer(InvocationOnMock invocation) throws Throwable {
        ((StringHolder)invocation.getArguments()[2]).value = status.toString();
        return null;
      }
      }).when(service).getMobileAuthenticateStatus(anyInt(), eq(false), any(StringHolder.class), any(StringHolder.class));
    return service;
  }

  private DigiDocServicePortType mockAuthentication(final String result, final String firstName, final String lastName, final String personalCode, final String challenge, final int sessCode) throws RemoteException {
    DigiDocServicePortType service = mock(DigiDocServicePortType.class);
    doAnswer(new Answer<Object>() {
      @Override
      public Object answer(InvocationOnMock invocation) throws Throwable {
        ((IntHolder)invocation.getArguments()[11]).value = sessCode;
        ((StringHolder)invocation.getArguments()[12]).value = result;
        ((StringHolder)invocation.getArguments()[13]).value = personalCode;
        ((StringHolder)invocation.getArguments()[14]).value = firstName;
        ((StringHolder)invocation.getArguments()[15]).value = lastName;
        ((StringHolder)invocation.getArguments()[19]).value = challenge;
        return null;
      }
    }).when(service).mobileAuthenticate(anyString(), anyString(), eq("37255667788"), anyString(),
        anyString(), anyString(), anyString(), anyString(), anyInt(), anyBoolean(), anyBoolean(), any(IntHolder.class),
        any(StringHolder.class), any(StringHolder.class), any(StringHolder.class), any(StringHolder.class), any(StringHolder.class),
        any(StringHolder.class), any(StringHolder.class), any(StringHolder.class), any(StringHolder.class), any(StringHolder.class));

    return service;
  }

  private DigiDocServicePortType mockError(int errorCode) throws RemoteException {
    DigiDocServicePortType service = mock(DigiDocServicePortType.class);
    doThrow(new RemoteException(valueOf(errorCode)))
    .when(service).mobileAuthenticate(anyString(), anyString(), eq("37255667788"), anyString(),
        anyString(), anyString(), anyString(), anyString(), anyInt(), anyBoolean(), anyBoolean(), any(IntHolder.class),
        any(StringHolder.class), any(StringHolder.class), any(StringHolder.class), any(StringHolder.class), any(StringHolder.class),
        any(StringHolder.class), any(StringHolder.class), any(StringHolder.class), any(StringHolder.class), any(StringHolder.class));

    return service;
  }
}
