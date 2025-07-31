/*
 * The MIT License
 *
 * Copyright (c) 2015, CloudBees, Inc., Stephen Connolly.
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

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsMatcher;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.OverrideMustInvoke;
import edu.umd.cs.findbugs.annotations.When;
import hudson.ExtensionPoint;
import org.apache.commons.lang3.ClassUtils;

/**
 * Converts {@link Credentials} into authentication tokens
 *
 * @since 1.0
 */
public abstract class AuthenticationTokenSource<T, C extends Credentials>
        implements ExtensionPoint {

    /**
     * The type of tokens that we produce.
     */
    private final Class<T> tokenClass;

    /**
     * The type of credentials that we consume.
     */
    private final Class<C> credentialsClass;

    /**
     * Constructor.
     *
     * @param tokenClass       the type of token produced.
     * @param credentialsClass the type of credentials consumed.
     */
    protected AuthenticationTokenSource(Class<T> tokenClass, Class<C> credentialsClass) {
        this.tokenClass = tokenClass;
        this.credentialsClass = credentialsClass;
    }

    /**
     * Converts the specified credentials into a token.
     *
     * @param credential the credentials to convert.
     * @return the corresponding token.
     * @throws AuthenticationTokenException if the specific credentials could not be converted.
     */
    @NonNull
    public abstract T convert(@NonNull C credential) throws AuthenticationTokenException;

    /**
     * Produces a {@link CredentialsMatcher} for this specific {@link AuthenticationTokenSource}.
     * Implementations only need to override this method when they can only process a sub-set of the
     * credential class that they convert. For example if {@link UsernamePasswordCredentials} are converted
     * into a specific authentication token, but only for those cases where there is a password and the username
     * is between 3 and 8 lowercase letters then the specific source implementation would likely override
     * this method and return a more specific {@link CredentialsMatcher} in order to avoid {@link #convert(Credentials)}
     * having to throw an {@link AuthenticationTokenException}.
     *
     * @return the {@link CredentialsMatcher} for this source.
     */
    @NonNull
    @OverrideMustInvoke(When.ANYTIME)
    public CredentialsMatcher matcher() {
        return CredentialsMatchers.instanceOf(credentialsClass);
    }

    /**
     * Checks if this source produces the specified token type.
     *
     * @param tokenClass the token type.
     * @param <T>        the token type.
     * @return {@code true} if and only if this source can produce tokens of the specified type.
     */
    public final <T> boolean produces(@NonNull Class<T> tokenClass) {
        return tokenClass.isAssignableFrom(this.tokenClass);
    }

    /**
     * Checks if this source consumes {@link Credentials} of the specified type.
     *
     * @param credentialsClass the credential type.
     * @param <C>              the credential type.
     * @return {@code true} if and only if this source can consume credentials of the specified type.
     */
    public final <C extends Credentials> boolean consumes(@NonNull Class<C> credentialsClass) {
        return this.credentialsClass.isAssignableFrom(credentialsClass);
    }

    /**
     * Checks if this source consumes the specific {@link Credentials} instance.
     *
     * @param credentials the credentials.
     * @return {@code true} if and only if this source can consume credentials of the specified type.
     */
    public final boolean consumes(@NonNull Credentials credentials) {
        return this.credentialsClass.isInstance(credentials) && matcher().matches(credentials);
    }

    /**
     * Checks if this source fits the specified context.
     * @param context the context that an authentication token is required in.
     * @return {@code true} if and only if this source fits the specified context.
     * @since 1.2
     */
    @SuppressWarnings("unchecked")
    public final boolean fits(AuthenticationTokenContext<?> context) {
        return produces(context.getTokenClass()) && isFit((AuthenticationTokenContext<? super T>) context);
    }

    /**
     * Checks if this source fits the specified context, override this method
     * @param context the context that an authentication token is required in.
     * @return {@code true} if and only if this source fits the specified context.
     * @since 1.2
     */
    protected boolean isFit(AuthenticationTokenContext<? super T> context) {
        return true;
    }

    /**
     * Score the goodness of match.
     * @param tokenClass the token class.
     * @param credentials the credentials instance.
     * @return the match score (higher the better) or {@code null} if not a match.
     * @since 1.1
     */
    /*package*/ final Integer score(Class<?> tokenClass, Credentials credentials) {
        if (!produces(tokenClass) || !consumes(credentials)) {
            return null;
        }
        short producerScore;
        if (this.tokenClass.equals(tokenClass)) {
            producerScore = Short.MAX_VALUE;
        } else {
            if (this.tokenClass.isInterface()) {
                // TODO compute a goodness of fit
                producerScore = 0;
            } else {
                producerScore = (short)ClassUtils.getAllSuperclasses(tokenClass).indexOf(this.tokenClass);
            }
        }
        short consumerScore;
        if (this.credentialsClass.equals(credentials.getClass())) {
            consumerScore = Short.MAX_VALUE;
        } else {
            if (this.credentialsClass.isInterface()) {
                // TODO compute a goodness of fit
                consumerScore = 0;
            } else {
                consumerScore = (short)ClassUtils.getAllSuperclasses(credentials.getClass()).indexOf(this.credentialsClass);
            }
        }
        return ((int)producerScore) << 16 | (int)consumerScore;
    }

    /**
     * Score the goodness of match.
     *
     * @param context     the context that an authentication token is required in.
     * @param credentials the credentials instance.
     * @return the match score (higher the better) or {@code null} if not a match.
     * @since 1.2
     */
    /*package*/
    final Integer score(AuthenticationTokenContext<?> context, Credentials credentials) {
        return fits(context) ? score(context.getTokenClass(), credentials) : null;
    }
}
