package jenkins.authentication.tokens.api;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;
import org.apache.commons.codec.binary.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.TestExtension;

import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

/**
 * @author Stephen Connolly
 */
public class AuthenticationTokenContextTest {
    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    public void smokes() {
        AuthenticationTokenContext<HttpAuthenticator> context = AuthenticationTokenContext.builder(HttpAuthenticator.class)
                .build();
        UsernamePasswordCredentials p =
                new UsernamePasswordCredentialsImpl(CredentialsScope.GLOBAL, "test", null, "bob", "secret");
        assertThat(AuthenticationTokens.matcher(context).matches(p), is(true));
        CertificateCredentialsImpl q = new CertificateCredentialsImpl(CredentialsScope.GLOBAL, "test2", null, null,
                new CertificateCredentialsImpl.UploadedKeyStoreSource((String) null));
        assertThat(AuthenticationTokens.matcher(context).matches(
                q), is(
                false));
        
        HttpAuthenticator authenticator = AuthenticationTokens.convert(context, p);
        assertThat(authenticator, notNullValue());
        assertThat(authenticator, instanceOf(HttpAuthenticator.class));
        assertThat(authenticator.getHeader("foo:"), anyOf(is(Util.getDigestOf("foo:bob:secret")),
                is(Base64.encodeBase64String("bob:secret".getBytes()))));
        
        context = AuthenticationTokenContext.builder(HttpAuthenticator.class)
                .with(HttpAuthenticator.class, "basic")
                .build();

        assertThat(AuthenticationTokens.matcher(context).matches(p), is(true));
        
        authenticator = AuthenticationTokens.convert(context, p);
        assertThat(authenticator, notNullValue());
        assertThat(authenticator, instanceOf(BasicAuthenticator.class));
        assertThat(authenticator.getHeader("foo:"), is(Base64.encodeBase64String("bob:secret".getBytes())));
        
        context = AuthenticationTokenContext.builder(HttpAuthenticator.class)
                .with(HttpAuthenticator.class, "digest")
                .build();

        assertThat(AuthenticationTokens.matcher(context).matches(p), is(true));
        
        authenticator = AuthenticationTokens.convert(context, p);
        assertThat(authenticator, notNullValue());
        assertThat(authenticator, instanceOf(DigestAuthenticator.class));
        assertThat(authenticator.getHeader("foo:"), is(Util.getDigestOf("foo:bob:secret")));

        authenticator = AuthenticationTokens.convert(context, q, p);
        assertThat(authenticator, notNullValue());
        assertThat(authenticator, instanceOf(DigestAuthenticator.class));
        assertThat(authenticator.getHeader("foo:"), is(Util.getDigestOf("foo:bob:secret")));

        context = AuthenticationTokenContext.builder(HttpAuthenticator.class)
                .with(HttpAuthenticator.class, "certificate")
                .build();

        assertThat(AuthenticationTokens.matcher(context).matches(p), is(false));
        
        authenticator = AuthenticationTokens.convert(context, p);
        assertThat(authenticator, nullValue());
    }

    public interface HttpAuthenticator {
        String getHeader(String request);
    }
    
    public static class DigestAuthenticator implements HttpAuthenticator {
        private final String value;

        public DigestAuthenticator(String value) {
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

            DigestAuthenticator that = (DigestAuthenticator) o;

            return !(value != null ? !value.equals(that.value) : that.value != null);

        }

        @Override
        public int hashCode() {
            return value != null ? value.hashCode() : 0;
        }

        @Override
        public String toString() {
            final StringBuilder sb = new StringBuilder("DigestAuthenticator{");
            sb.append("value='").append(value).append('\'');
            sb.append('}');
            return sb.toString();
        }

        public String getHeader(String request) {
            // we are only running tests, so screw the fact that MD5 is a crappy digest scheme
            return Util.getDigestOf(request + value);
        }
        
    }

    public static class BasicAuthenticator implements HttpAuthenticator {
        private final String value;

        public BasicAuthenticator(String value) {
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

            BasicAuthenticator that = (BasicAuthenticator) o;

            return !(value != null ? !value.equals(that.value) : that.value != null);

        }

        @Override
        public int hashCode() {
            return value != null ? value.hashCode() : 0;
        }

        @Override
        public String toString() {
            final StringBuilder sb = new StringBuilder("BasicAuthenticator{");
            sb.append("value='").append(value).append('\'');
            sb.append('}');
            return sb.toString();
        }

        public String getHeader(String request) {
            // we are only running tests, so screw the fact we are using system encoding
            return Base64.encodeBase64String(value.getBytes());
        }
    }

    @TestExtension
    public static class UserPassToDigest extends AuthenticationTokenSource<DigestAuthenticator, UsernamePasswordCredentials> {

        public UserPassToDigest() {
            super(DigestAuthenticator.class, UsernamePasswordCredentials.class);
        }

        @NonNull
        @Override
        public DigestAuthenticator convert(@NonNull UsernamePasswordCredentials credential)
                throws AuthenticationTokenException {
            return new DigestAuthenticator(String.format("%s:%s", credential.getUsername(), credential.getPassword().getPlainText()));
        }

        @Override
        protected boolean isFit(AuthenticationTokenContext<? super DigestAuthenticator> context) {
            return context.canHave(HttpAuthenticator.class, "digest");
        }
    }
    
    @TestExtension
    public static class UserPassToBasic extends AuthenticationTokenSource<BasicAuthenticator, UsernamePasswordCredentials> {

        public UserPassToBasic() {
            super(BasicAuthenticator.class, UsernamePasswordCredentials.class);
        }

        @NonNull
        @Override
        public BasicAuthenticator convert(@NonNull UsernamePasswordCredentials credential)
                throws AuthenticationTokenException {
            return new BasicAuthenticator(String.format("%s:%s", credential.getUsername(), credential.getPassword().getPlainText()));
        }

        @Override
        protected boolean isFit(AuthenticationTokenContext<? super BasicAuthenticator> context) {
            return context.canHave(HttpAuthenticator.class, "basic");
        }
    }
    
}
