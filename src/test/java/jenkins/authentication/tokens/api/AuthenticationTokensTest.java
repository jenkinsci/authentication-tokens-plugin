package jenkins.authentication.tokens.api;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SecretBytes;
import com.cloudbees.plugins.credentials.common.StandardCertificateCredentials;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

/**
 * @author Stephen Connolly
 */
@WithJenkins
class AuthenticationTokensTest {

    @Test
    void smokes(JenkinsRule j) throws Exception {
        UsernamePasswordCredentials p =
                new UsernamePasswordCredentialsImpl(CredentialsScope.GLOBAL, "test", null, "bob", "secret");
        StandardCertificateCredentials cc = new CertificateCredentialsImpl(CredentialsScope.GLOBAL, "test2", null, "password",
                    new CertificateCredentialsImpl.UploadedKeyStoreSource(null, dummyPKCS12Store("password")));

        assertThat(AuthenticationTokens.matcher(DigestToken.class).matches(p), is(true));
        assertThat(AuthenticationTokens.matcher(DigestToken.class).matches(cc), is(false));
        assertThat(AuthenticationTokens.convert(DigestToken.class, p),
                is(new DigestToken(Util.getDigestOf("bob:secret"))));
    }

    public static class DigestToken {
        private final String value;

        public DigestToken(String value) {
            this.value = value;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }

            DigestToken that = (DigestToken) o;

            return !(value != null ? !value.equals(that.value) : that.value != null);

        }

        @Override
        public int hashCode() {
            return value != null ? value.hashCode() : 0;
        }

        @Override
        public String toString() {
            final StringBuilder sb = new StringBuilder("DigestToken{");
            sb.append("value='").append(value).append('\'');
            sb.append('}');
            return sb.toString();
        }
    }

    @TestExtension
    public static class UserPassToDigest extends AuthenticationTokenSource<DigestToken, UsernamePasswordCredentials> {

        public UserPassToDigest() {
            super(DigestToken.class, UsernamePasswordCredentials.class);
        }

        @NonNull
        @Override
        public DigestToken convert(@NonNull UsernamePasswordCredentials credential)
                throws AuthenticationTokenException {
            // this is so totally insecure as a token, but it works as an example
            return new DigestToken(Util.getDigestOf(
                    String.format("%s:%s", credential.getUsername(), credential.getPassword().getPlainText())));
        }
    }

    private static SecretBytes dummyPKCS12Store(String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, password.toCharArray());
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ks.store(bos, password.toCharArray());
        return SecretBytes.fromBytes(bos.toByteArray());
    }
}
