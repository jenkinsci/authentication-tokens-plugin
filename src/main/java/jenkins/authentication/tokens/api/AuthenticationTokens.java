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
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import jenkins.model.Jenkins;

/**
 * Utility class for manipulating authentication tokens.
 *
 * @since 1.0
 */
public final class AuthenticationTokens {

    /**
     * Our logger.
     */
    private static final Logger LOGGER = Logger.getLogger(AuthenticationTokens.class.getName());

    /**
     * Do not instantiate this utility class.
     */
    private AuthenticationTokens() {
        throw new IllegalAccessError("Utility class");
    }

    /**
     * Builds a matcher for credentials that can be converted into the supplied token type.
     *
     * @param tokenClass the type of token
     * @param <T>        the type of token
     * @return a matcher for the type of token
     */
    public static <T> CredentialsMatcher matcher(Class<T> tokenClass) {
        return matcher(new AuthenticationTokenContext<T>(tokenClass));
    }

    /**
     * Builds a matcher for credentials that can be converted into the supplied token type.
     *
     * @param context    the context that an authentication token is required in.
     * @param <T>        the type of token.
     * @return a matcher for the type of token.
     * @since 1.2
     */
    public static <T> CredentialsMatcher matcher(AuthenticationTokenContext<T> context) {
        List<CredentialsMatcher> matchers = new ArrayList<CredentialsMatcher>();
        Jenkins jenkins = Jenkins.getInstance();
        if(jenkins == null){
            LogRecord lr = new LogRecord(Level.FINE,
                "No Jenkins object was found; no match could be made.");
            LOGGER.log(lr);
            return CredentialsMatchers.never();
        }
        for (AuthenticationTokenSource<?, ?> source : jenkins
                .getExtensionList(AuthenticationTokenSource.class)) {
            if (source.fits(context)) {
                matchers.add(source.matcher());
            }
        }
        return matchers.isEmpty()
                ? CredentialsMatchers.never()
                : CredentialsMatchers.anyOf(matchers.toArray(new CredentialsMatcher[matchers.size()]));
    }

    /**
     * Converts the supplied credentials into the specified token.
     *
     * @param type        the type of token to convert to.
     * @param credentials the credentials instance to convert.
     * @param <T>         the type of token to convert to.
     * @param <C>         the type of credentials to convert,
     * @return the token or {@code null} if the credentials could not be converted.
     */
    @SuppressWarnings("unchecked")
    @CheckForNull
    public static <T, C extends Credentials> T convert(@NonNull Class<T> type, @CheckForNull C credentials) {
        if (credentials == null) {
            return null;
        }
        return convert(new AuthenticationTokenContext<T>(type), credentials);
    }

    /**
     * Converts the supplied credentials into the specified token.
     *
     * @param context     the context that an authentication token is required in.
     * @param credentials the credentials instance to convert.
     * @param <T>         the type of token to convert to.
     * @param <C>         the type of credentials to convert,
     * @return the token or {@code null} if the credentials could not be converted.
     * @since 1.2
     */
    @SuppressWarnings("unchecked")
    @CheckForNull
    public static <T, C extends Credentials> T convert(@NonNull AuthenticationTokenContext<T> context, @CheckForNull C credentials) {
        if (credentials == null) {
            return null;
        }
        // we want the best match first
        SortedMap<Integer,AuthenticationTokenSource> matches = new TreeMap<Integer, AuthenticationTokenSource>(
                Collections.reverseOrder());
        Jenkins jenkins = Jenkins.getInstance();
        if(jenkins == null){
            LogRecord lr = new LogRecord(Level.FINE,
                "No Jenkins object was found; no conversion could be made.");
            LOGGER.log(lr);
            return null;
        }
        for (AuthenticationTokenSource<?, ?> source : jenkins
                .getExtensionList(AuthenticationTokenSource.class)) {
            Integer score = source.score(context, credentials);
            if (score != null && !matches.containsKey(score)) {
                // if there are two extensions with the same score, 
                // then the first (i.e. highest Extension.ordinal should win)
                matches.put(score, source);
            }
        }
        // now try all the matches (form best to worst) until we get a conversion 
        for (AuthenticationTokenSource<?,?> source: matches.values()) {
            if (source.produces(context.getTokenClass()) && source.consumes(credentials)) { // redundant test, but for safety
                AuthenticationTokenSource<? extends T, ? super C> s =
                        (AuthenticationTokenSource<? extends T, ? super C>) source;
                T token = null;
                try {
                    token = s.convert(credentials);
                } catch (AuthenticationTokenException e) {
                    LogRecord lr = new LogRecord(Level.FINE,
                            "Could not convert credentials {0} into token of type {1} using source {2}: {3}");
                    lr.setThrown(e);
                    lr.setParameters(new Object[]{credentials, context.getTokenClass(), s, e.getMessage()});
                    LOGGER.log(lr);
                }
                if (token != null) {
                    return token;
                }
            }
        }
        
        return null;
    }

    /**
     * Converts the best match of the supplied credentials into the specified token.
     *
     * @param context     the context that an authentication token is required in.
     * @param credentials the credentials instances to try and convert.
     * @param <T>         the type of token to convert to.
     * @param <C>         the type of credentials to convert,
     * @return the token or {@code null} if the credentials could not be converted.
     * @since 1.2
     */
    @SuppressWarnings("unchecked")
    @CheckForNull
    public static <T, C extends Credentials> T convert(@NonNull AuthenticationTokenContext<T> context,
                                                       @NonNull C... credentials) {
        return convert(context, Arrays.asList(credentials));
    }

    /**
     * Converts the best match of the supplied credentials into the specified token.
     *
     * @param context     the context that an authentication token is required in.
     * @param credentials the credentials instances to try and convert.
     * @param <T>         the type of token to convert to.
     * @param <C>         the type of credentials to convert,
     * @return the token or {@code null} if the credentials could not be converted.
     * @since 1.2
     */
    @SuppressWarnings("unchecked")
    @CheckForNull
    public static <T, C extends Credentials> T convert(@NonNull AuthenticationTokenContext<T> context,
                                                       @NonNull List<C> credentials) {
        // we want the best match first
        SortedMap<Integer, Map.Entry<C, AuthenticationTokenSource>> matches =
                new TreeMap<Integer, Map.Entry<C, AuthenticationTokenSource>>(
                        Collections.reverseOrder());
                        
        Jenkins jenkins = Jenkins.getInstance();
        if(jenkins == null){
            LogRecord lr = new LogRecord(Level.FINE,
                "No Jenkins object was found; no conversion could be made.");
            LOGGER.log(lr);
            return null;
        }
        for (C credential : credentials) {
            for (AuthenticationTokenSource<?, ?> source : jenkins
                    .getExtensionList(AuthenticationTokenSource.class)) {
                Integer score = source.score(context, credential);
                if (score != null && !matches.containsKey(score)) {
                    // if there are two extensions with the same score,
                    // then the first (i.e. highest Extension.ordinal should win)
                    // if there are two credentials with the same scoe,
                    // then the first in the list should win.
                    matches.put(score, new AbstractMap.SimpleEntry<C, AuthenticationTokenSource>(credential, source));
                }
            }
        }
        // now try all the matches (form best to worst) until we get a conversion
        for (Map.Entry<C, AuthenticationTokenSource> entry : matches.values()) {
            C credential = entry.getKey();
            AuthenticationTokenSource source = entry.getValue();
            if (source.produces(context.getTokenClass()) && source
                    .consumes(credential)) { // redundant test, but for safety
                AuthenticationTokenSource<? extends T, ? super C> s =
                        (AuthenticationTokenSource<? extends T, ? super C>) source;
                T token = null;
                try {
                    token = s.convert(credential);
                } catch (AuthenticationTokenException e) {
                    LogRecord lr = new LogRecord(Level.FINE,
                            "Could not convert credentials {0} into token of type {1} using source {2}: {3}");
                    lr.setThrown(e);
                    lr.setParameters(new Object[]{credentials, context.getTokenClass(), s, e.getMessage()});
                    LOGGER.log(lr);
                }
                if (token != null) {
                    return token;
                }
            }
        }

        return null;
    }

}
