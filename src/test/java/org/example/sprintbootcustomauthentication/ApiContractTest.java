package org.example.sprintbootcustomauthentication;

import com.jayway.jsonpath.JsonPath;
import org.example.sprintbootcustomauthentication.auth.AuthController;
import org.example.sprintbootcustomauthentication.auth.AuthenticationService;
import org.example.sprintbootcustomauthentication.auth.MeController;
import org.example.sprintbootcustomauthentication.auth.TokenController;
import org.example.sprintbootcustomauthentication.security.SecurityConfig;
import org.example.sprintbootcustomauthentication.token.AccessTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Fails when the controllers and the Smithy model (api-model/model/auth.smithy) disagree about
 * which HTTP operations exist. Run through Gradle so the OpenAPI document is generated first.
 */
@WebMvcTest({AuthController.class, TokenController.class, MeController.class})
@Import(SecurityConfig.class)
@ActiveProfiles("dev")
class ApiContractTest {

    private static final String DEFAULT_OPENAPI_FILE =
            "api-model/build/smithyprojections/api-model/source/openapi/AuthService.openapi.json";

    @Autowired
    RequestMappingHandlerMapping handlerMapping;

    @MockitoBean
    AccessTokenService accessTokenService;

    @MockitoBean
    AuthenticationService authenticationService;

    @Test
    void controllersExposeExactlyTheOperationsInTheSmithyModel() throws IOException {
        // given
        Set<String> documented = documentedOperations();

        // when
        Set<String> implemented = implementedOperations();

        // then
        assertThat(implemented)
                .as("operations implemented by the controllers")
                .containsExactlyInAnyOrderElementsOf(documented);
    }

    private Set<String> documentedOperations() throws IOException {
        File file = new File(System.getProperty("openapi.file", DEFAULT_OPENAPI_FILE));
        assertThat(file)
                .as("generated OpenAPI document (run ./gradlew :api-model:smithyBuild)")
                .exists();

        Map<String, Map<String, Object>> paths = JsonPath.parse(Files.readString(file.toPath())).read("$.paths");
        Set<String> operations = new TreeSet<>();
        paths.forEach((path, byMethod) ->
                byMethod.keySet().forEach(method -> operations.add(method.toUpperCase() + " " + path)));
        return operations;
    }

    private Set<String> implementedOperations() {
        Set<String> operations = new TreeSet<>();
        for (RequestMappingInfo info : handlerMapping.getHandlerMethods().keySet()) {
            Set<String> patterns = info.getPathPatternsCondition().getPatternValues();
            for (String pattern : patterns) {
                if (isPartOfTheContract(pattern)) {
                    info.getMethodsCondition().getMethods()
                            .forEach(method -> operations.add(method.name() + " " + pattern));
                }
            }
        }
        return operations;
    }

    private boolean isPartOfTheContract(String pattern) {
        return pattern.startsWith("/auth/") || pattern.equals("/me");
    }
}
