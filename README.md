Jenkins Authentication Tokens API Plugin
=====================

This plugin provides an API for converting credentials into
authentication tokens in Jenkins.

  
The plugin provides concepts for:

-   Authentication Token Source: converts a type of Credentials into
    authentication tokens of a certain type.
-   Authentication Token Context: used to specify the context in which
    the token wants to be used through a series of purposes.
-   AuthenticationTokens utility class to generate matchers and convert
    credentials into tokens easily. 

Development
===========

Start the local Jenkins instance:

    mvn hpi:run


How to install
--------------

Run

    mvn clean package

to create the plugin .hpi file.


To install:

1. copy the resulting ./target/credentials.hpi file to the $JENKINS_HOME/plugins directory. Don't forget to restart Jenkins afterwards.

2. or use the plugin management console (http://example.com:8080/pluginManager/advanced) to upload the hpi file. You have to restart Jenkins in order to find the pluing in the installed plugins list.


Plugin releases
---------------

Releases are performed [automatically](https://www.jenkins.io/doc/developer/publishing/releasing-cd/) for merged pull requests with interesting labels.


License
-------

    (The MIT License)

    Copyright © 2015, CloudBees, Inc., Stephen Connolly.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
