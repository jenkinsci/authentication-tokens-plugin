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

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import net.jcip.annotations.NotThreadSafe;
import net.jcip.annotations.ThreadSafe;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The context within which an authentication token will be used.
 *
 * @param <T> the type of token
 * @since 1.2
 */
@ThreadSafe
public final class AuthenticationTokenContext<T> {
    /**
     * The base class
     */
    @NonNull
    private final Class<T> tokenClass;
    /**
     * The optional purposes for which the token will be used.
     */
    @CheckForNull
    private final Map<Object, Object> purposes;

    /**
     * Creates a basic context for any purpose.
     *
     * @param tokenClass the type of token.
     */
    public AuthenticationTokenContext(@NonNull Class<T> tokenClass) {
        this(tokenClass, null);
    }

    /**
     * Creates a context with the specified purposes.
     *
     * @param tokenClass the type of token.
     * @param purposes   the purposes.
     */
    private AuthenticationTokenContext(@NonNull Class<T> tokenClass, @CheckForNull Map<Object, Object> purposes) {
        this.tokenClass = tokenClass;
        this.purposes = purposes;
    }

    /**
     * Creates a {@link Builder} for contexts of the specified token type.
     *
     * @param tokenClass the type of token.
     * @param <T>        the type of token.
     * @return a {@link Builder} instance.
     */
    public static <T> Builder<T> builder(@NonNull Class<T> tokenClass) {
        return new Builder<T>(tokenClass);
    }

    /**
     * Returns the type of token.
     *
     * @return the type of token.
     */
    @NonNull
    public Class<T> getTokenClass() {
        return tokenClass;
    }

    /**
     * Checks if the context specifies the supplied purpose and matches against the valid values.
     *
     * @param purpose     the purpose.
     * @param validValues the valid values that the purpose must match if specified.
     * @return {@code true} if either the purpose is not specified or the purpose is specified and is equal
     * to one of the specified values.
     */
    public boolean canHave(@NonNull Object purpose, Object... validValues) {
        if (purposes == null || !purposes.containsKey(purpose)) {
            // we do not have a counter purpose
            return true;
        }
        Object value = purposes.get(purpose);
        for (Object valid : validValues) {
            if (value == null ? valid == null : value.equals(valid)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Ensures the context specifies the supplied purpose matching against the valid values.
     *
     * @param purpose     the purpose.
     * @param validValues the valid values that the purpose must match.
     * @return {@code true} if and only if the purpose is specified and is equal to one of the specified values.
     */
    public boolean mustHave(@NonNull Object purpose, Object... validValues) {
        if (purposes == null || !purposes.containsKey(purpose)) {
            return false;
        }
        Object value = purposes.get(purpose);
        for (Object valid : validValues) {
            if (value == null ? valid == null : value.equals(valid)) {
                return true;
            }
        }
        return false;
    }

    /**
     * A non-thread safe builder of {@link AuthenticationTokenContext} instances.
     *
     * @param <T> the token type.
     * @since 1.2
     */
    @NotThreadSafe
    public static final class Builder<T> {

        /**
         * The token type.
         */
        @NonNull
        private final Class<T> tokenClass;
        /**
         * The purposes.
         */
        @CheckForNull
        private Map<Object, Object> purposes = null;

        /**
         * Constructs a new builder.
         *
         * @param tokenClass the token type.
         */
        private Builder(@NonNull Class<T> tokenClass) {
            this.tokenClass = tokenClass;
        }

        /**
         * Specifies the supplied purpose (with value {@link Boolean#TRUE}).
         *
         * @param purpose the purpose.
         * @return {@code this} for method chaining.
         */
        @NonNull
        public Builder<T> with(@NonNull Object purpose) {
            return with(purpose, Boolean.TRUE);
        }

        /**
         * Specifies the supplied purpose with the specified value.
         *
         * @param purpose the purpose.
         * @param value   the value.
         * @return {@code this} for method chaining.
         */
        @NonNull
        public Builder<T> with(@NonNull Object purpose, @CheckForNull Object value) {
            if (purposes == null) {
                purposes = new LinkedHashMap<Object, Object>();
            }
            purposes.put(purpose, value);
            return this;
        }

        /**
         * Instantiates the {@link AuthenticationTokenContext}.
         *
         * @return the {@link AuthenticationTokenContext}.
         */
        @NonNull
        public AuthenticationTokenContext<T> build() {
            return new AuthenticationTokenContext<T>(tokenClass,
                    purposes == null || purposes.isEmpty() ? null : purposes);
        }
    }

}
