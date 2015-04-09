package jenkins.authentication.tokens.api;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.TestExtension;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

/**
 * @author Stephen Connolly
 */
public class AuthenticationTokensTest {
    
    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    public void smokes() {
        UsernamePasswordCredentials p =
                new UsernamePasswordCredentialsImpl(CredentialsScope.GLOBAL, "test", null, "bob", "secret");
        assertThat(AuthenticationTokens.matcher(DigestToken.class).matches(p), is(true));
        assertThat(AuthenticationTokens.matcher(DigestToken.class).matches(new CertificateCredentialsImpl(CredentialsScope.GLOBAL, "test2", null, null, new CertificateCredentialsImpl.UploadedKeyStoreSource(null))), is(false));
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
}
