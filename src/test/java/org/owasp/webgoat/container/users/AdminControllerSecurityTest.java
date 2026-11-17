/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.Mockito.doThrow;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.webgoat.container.WebGoat;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Pruebas negativas de seguridad sobre los endpoints de administración (/service/admin/**).
 *
 * <p>A diferencia de {@link AdminControllerTest} (MockMvc standalone, sin seguridad), aquí se
 * levanta el contexto completo con la cadena de filtros de Spring Security, para verificar que el
 * sistema rechaza lo que debe rechazar:
 *
 * <ul>
 *   <li>Autorización: un usuario sin rol de administrador recibe 403.
 *   <li>Autenticación: una petición sin sesión recibe 401 (AJAX) o se redirige al login.
 *   <li>Validación de entradas: un username malicioso o con formato inválido recibe 400.
 *   <li>Manejo de errores: un fallo interno responde 500 sin trazas ni detalles internos.
 * </ul>
 */
@SpringBootTest(classes = WebGoat.class)
@TestPropertySource(
    locations = {
      "classpath:/application-webgoat.properties",
      "classpath:/application-webgoat-test.properties"
    })
class AdminControllerSecurityTest {

  private static final WebGoatUser REGULAR_USER =
      new WebGoatUser("regular-user", "password", WebGoatUser.ROLE_USER);
  private static final WebGoatUser ADMIN_USER =
      new WebGoatUser("admin-user", "password", WebGoatUser.ROLE_ADMIN);

  @Autowired private WebApplicationContext wac;
  @MockitoSpyBean private UserService userService;
  @MockitoBean private ClientRegistrationRepository clientRegistrationRepository;

  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    mockMvc = MockMvcBuilders.webAppContextSetup(wac).apply(springSecurity()).build();
  }

  // ── 1. Autorización ────────────────────────────────────────────────────────

  @Test
  void usuarioSinRolAdminNoPuedeListarUsuarios() throws Exception {
    mockMvc
        .perform(get("/service/admin/users").with(user(REGULAR_USER)))
        .andExpect(status().isForbidden());
  }

  @Test
  void usuarioSinRolAdminNoPuedeResetearContrasenaDeOtro() throws Exception {
    mockMvc
        .perform(post("/service/admin/users/webgoat-admin/reset-password").with(user(REGULAR_USER)))
        .andExpect(status().isForbidden());
  }

  // ── 2. Autenticación ───────────────────────────────────────────────────────

  @Test
  void peticionAjaxSinSesionEsRechazadaCon401() throws Exception {
    mockMvc
        .perform(get("/service/admin/users").header("X-Requested-With", "XMLHttpRequest"))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void navegacionSinSesionSeRedirigeAlLogin() throws Exception {
    mockMvc
        .perform(get("/service/admin/users"))
        .andExpect(status().is3xxRedirection())
        .andExpect(
            result ->
                org.assertj.core.api.Assertions.assertThat(
                        result.getResponse().getRedirectedUrl())
                    .contains("/login"));
  }

  // ── 3. Validación de entradas ──────────────────────────────────────────────

  @ParameterizedTest
  @ValueSource(
      strings = {
        "' OR '1'='1",
        "<img src=x onerror=alert(1)>",
        "..%2F..%2Fetc%2Fpasswd",
        "ADMIN",
        "usuario-con-un-nombre-demasiado-largo-para-ser-valido-xx"
      })
  void usernameInvalidoEsRechazadoCon400(String username) throws Exception {
    mockMvc
        .perform(get("/service/admin/users/{username}", username).with(user(ADMIN_USER)))
        .andExpect(status().isBadRequest());
  }

  // ── 4. Manejo de errores ───────────────────────────────────────────────────

  @Test
  void errorInternoNoExponeDetalles() throws Exception {
    doThrow(new IllegalStateException("fallo en BD: tabla CONTAINER.WEB_GOAT_USER"))
        .when(userService)
        .getAllUsers();

    mockMvc
        .perform(get("/service/admin/users").with(user(ADMIN_USER)))
        .andExpect(status().isInternalServerError())
        .andExpect(jsonPath("$.correlationId").exists())
        .andExpect(content().string(not(containsString("IllegalStateException"))))
        .andExpect(content().string(not(containsString("fallo en BD"))))
        .andExpect(content().string(not(containsString("at org.owasp"))));
  }
}
