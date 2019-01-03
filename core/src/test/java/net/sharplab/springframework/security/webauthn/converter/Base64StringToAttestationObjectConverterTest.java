package net.sharplab.springframework.security.webauthn.converter;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.response.attestation.AttestationObject;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class Base64StringToAttestationObjectConverterTest {

    private Registry registry = new Registry();

    @Test
    public void convert_test() {
        AttestationObject expected = TestUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        String source = new AttestationObjectConverter(registry).convertToString(expected);
        Base64StringToAttestationObjectConverter converter = new Base64StringToAttestationObjectConverter(registry);
        AttestationObject result = converter.convert(source);
        assertThat(result).isEqualTo(expected);
    }
}