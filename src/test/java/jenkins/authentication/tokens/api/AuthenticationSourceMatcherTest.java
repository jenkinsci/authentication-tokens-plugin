/*
 * The MIT License
 *
 * Copyright (c) 2015 CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package jenkins.authentication.tokens.api;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.TestExtension;
import static org.junit.Assert.*;

/**
 * Tests for {@link AuthenticationSourceMatcher}.
 * @author Oleg Nenashev
 */
public class AuthenticationSourceMatcherTest {
    
    @Rule
    public JenkinsRule j = new JenkinsRule();
    
    @Test
    public void findWithSourceMatcher() throws Exception {
        UsernamePasswordCredentials p =
                new UsernamePasswordCredentialsImpl(CredentialsScope.GLOBAL, "test", null, "bob", "secret");
        
        final Token t1 = AuthenticationTokens.convert(Token.class, p, new TokenSourceMatcher(1));
        assertTrue(t1 != null && t1.number == 1);
        
        final Token t2 = AuthenticationTokens.convert(Token.class, p, new TokenSourceMatcher(2));
        assertTrue(t2 != null && t2.number == 2);
    }
    
    
    public static class TokenSourceMatcher extends AuthenticationSourceMatcher {

        int requiredNumber;

        public TokenSourceMatcher(int requiredNumber) {
            this.requiredNumber = requiredNumber;
        }

        @Override
        public boolean matches(AuthenticationTokenSource item) {
            if (item instanceof TokenSource) {
                int number = ((TokenSource)item).number;
                return number == requiredNumber;
            }
            return false;
        }
        
    }
    
    public static class Token {
        private final int number;

        public Token(int number) {
            this.number = number;
        }      

        @Override
        public String toString() {
            return "number="+number;
        }    
    }
    
    public abstract static class TokenSource extends AuthenticationTokenSource<Token, UsernamePasswordCredentials> {
        int number;

        public TokenSource(int number) {
            super(Token.class, UsernamePasswordCredentials.class);
            this.number = number;
        }      
        
        @NonNull
        @Override
        public Token convert(@NonNull UsernamePasswordCredentials credential)
                throws AuthenticationTokenException {
            return new Token(number);
        }
    }
    
    @TestExtension
    public static class TokenSource1 extends TokenSource {
        public TokenSource1() {
            super(1);
        }    
    }
    
    @TestExtension
    public static class TokenSource2 extends TokenSource {
        public TokenSource2() {
            super(2);
        }    
    }
}
