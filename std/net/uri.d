//Written in the D programming language

/++
 + Parser for URIs which makes it easier to access its components.
 + 
 + The URI will be split up into the following components:
 + $(UL
 +     $(LI $(D scheme))
 +     $(LI $(D authority) $(UL
 +         $(LI $(D userinfo) $(UL
 +             $(LI $(D username))
 +             $(LI $(D password))
 +         ))
 +         $(LI $(D host))
 +         $(LI $(D port))
 +     ))
 +     $(LI $(D path))
 +     $(LI $(D query))
 +     $(LI $(D fragment))
 + )
 + 
 + Its usage is quite straightforward; to parse an URI, the user should give the string to the constructor as follows:
 + -------
 + auto u = URI("http://dlang.org/");
 + -------
 + From this point on, components of the URI can be both read and altered.
 + 
 + This is also possible without first parsing an URI. An empty struct can always be created.
 + -------
 + auto u = URI();
 + u.scheme = "https";
 + u.host = "github.com";
 + -------
 + 
 + Example:
 + -------
 + auto u = URI("http://www.puremagic.com/");
 + u.host = "d.puremagic.com";
 + u.path = ["issues", "show_bug.cgi"];
 + u.query = ["id": "8980"];
 + writeln(u);
 + -------
 + 
 + Example:
 + -------
 + auto u = URI("http://dlang.org/");
 + u.rawPath = "phobos/std_stdio.html";
 + u.fragment = "writeln";
 + assert(u == "http://dlang.org/phobos/std_stdio.html#writeln");
 + -------
 + 
 + Note:        There are multiple ways to read and/or alter the path and query of an URI and they can all be used interchangeably.
 + Standards:   Conforms to RFC 3986
 + References:  $(LINK2 http://en.wikipedia.org/wiki/URI_scheme, URI scheme), 
 +              $(LINK2 http://tools.ietf.org/html/rfc3986, RFC 3986)
 +
 + Copyright:   Copyright 2012
 + License:     $(LINK2 http://www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
 + Authors:     $(LINK2 mailto:dlang [replace-with-at-sign] mikevandongen.nl, Mike van Dongen)
 + Source:      $(PHOBOSSRC std/net/_uri.d)
 +/
module std.net.uri;

private import std.ascii : letters, digits, isAlpha;
private import std.string : indexOf, toLower, munch;
private import std.conv : to;
private import std.exception : enforce, assertThrown;
private import std.array : split, join;

struct URI
{
    private
    {
        string              _rawPath;
        string              _rawQuery;
        string[]            _path;
        string[][string]    _query;
    }
    
    public
    {
        string              scheme;
        string              username;
        string              password;
        string              host;
        int                 port;
        string              fragment;
    }
    
    @property string authority() const
    {
        string rawAuthority = userinfo;
        if(rawAuthority.length != 0)
            rawAuthority ~= "@";
        rawAuthority ~= host;
        if(port != 0)
            rawAuthority ~= ":" ~ to!string(port);
        return rawAuthority;
    }
    @property string authority(string value)
    {
        if(value.length == 0)
        {
            username = username.init;
            password = password.init;
            host = host.init;
            port = port.init;
            return value;
        }
        
        string rawAuthority = value;
        int i = cast(int) indexOf(value, "@");
        if(i != -1)                                                         // Check if it contains userinfo.
        {
            string userinfo = value[0 .. i];
            value = value[i+1 .. $];
            
            i = cast(int) indexOf(userinfo, ":");
            if(i != -1)                                                     // Check if it has a password.
            {
                password = userinfo[i+1 .. $];
                userinfo = userinfo[0 .. i];
            }
            else
                password = password.init;
            
            username = userinfo;
        }
        else
        {
            username = username.init;
            password = password.init;
        }
        
        bool ipLiteral = false;
        if(value[0] == '[')                                                 // Check if it's an IPv6 address (aka IP literal).
        {
            i = cast(int) indexOf(value, "]");
            enforce(i != -1, "An IPv6 address should always end with the character ']'!");
            host = value[0 .. i+1];
            value = value[i+1 .. $];
            ipLiteral = true;
        }
        
        i = cast(int) indexOf(value, ":");
        if(i != -1)                                                         // Check if it contains a port number.
        {
            if(ipLiteral)                                                   // If it has a portnumber, it should be immediately after the IPv6 address.
                enforce(!i, "There can't be anything between the host and the port besides the character ':'!");
            
            port = to!int(value[i+1 .. $]);
            value = value[0 .. i];
        }
        else
            port = port.init;
        
        if(!ipLiteral)                                                      // If it's an IPv6 address, then we've already assigned it.
            host = value;
        
        return rawAuthority;
    }
    
    @property string rawPath() const { return _rawPath; }
    @property string rawPath(const string value)
    {
        _path = split(value, "/");
        return _rawPath = value;
    }
    
    @property const(string[]) path() const { return _path; }
    @property string[] path(string[] value)
    {
        _rawPath = join(value, "/");
        return _path = value;
    }
    
    @property string rawQuery() const { return _rawQuery; }
    @property string rawQuery(const string value)
    {
        auto pairs = split(value, "&");
        string[][string] newQuery;
        foreach(q; pairs)
        {
            auto pair = indexOf(q, "=");
            if(pair == -1)
                newQuery[q] ~= "";
            else
                newQuery[q[0 .. pair]] ~= q[pair+1 .. $];
        }
        _query = newQuery;
        return _rawQuery = value;
    }
    
    @property string[string] query() const
    {
        string[string] q;
        foreach(k, v; _query)
            q[k] = v[$-1];
        return q;
    }
    @property string[string] query(string[string] value)
    {
        string[][string] q;
        foreach(k, v; value)
            q[k] ~= v;
        queryMulti = q;
        return value;
    }
    
    @property const(string[][string]) queryMulti() const { return _query; }
    @property string[][string] queryMulti(string[][string] value)
    {
        string newRawQuery;
        foreach(k, v; value)
            foreach(rv; v)
                newRawQuery ~= "&" ~ k ~ "=" ~ rv;
        if(newRawQuery.length != 0)
            newRawQuery = newRawQuery[1 .. $];
        _rawQuery = newRawQuery;
        return _query = value;
    }
    
    @property string userinfo() const
    {
        string userinfo = username;
        if(username.length != 0 && password.length != 0)
            userinfo ~= ":" ~ password;
        return userinfo;
    }
    
    const string toString() const
    {
        string uri = scheme ~ ":";
        string a = authority;
        if(a.length != 0)
            uri ~= "//" ~ a ~ "/";
        uri ~= _rawPath;
        if(_rawQuery.length != 0)
            uri ~= "?" ~ _rawQuery;
        if(fragment.length != 0)
            uri ~= "#" ~ fragment;
        return uri;
    }
    
    bool opEquals(const URI o) const    // If I remove the 2 const, the code coverage will be 100%. I believe it's because of a bug.
    {
        return 
            _path     == o._path &&
            _query    == o._query &&
            scheme    == o.scheme &&
            username  == o.username &&
            password  == o.password &&
            host      == o.host &&
            port      == o.port &&
            fragment  == o.fragment;
    }
    
    bool opEquals(const string b) const
    {
        return toString() == b;
    }
    
    this(in string requestUri)
    {
        string rawUri = requestUri;
        
        enforce(requestUri.length > 1, "The URI must start with a letter!");                // An URI has atleast 1 alpha character and a ':'.
        
        enforce(isAlpha(rawUri[0]), "The URI must start with a letter!");                   // The URI must start with a lower case letter.
        
        scheme = toLower(munch(rawUri, letters ~ digits ~ "+.-"));                          // 'Collects' the characters that are considered to be part of the scheme.
        enforce(rawUri.length && rawUri[0] == ':', "The scheme must end with the character ':'!");
        
        if(rawUri.length < 3 || rawUri[1 .. 3] != "//")                                     // If the URI doesn't continue with '//', than the remainder will be the path.
        {
            rawPath = rawUri[1 .. $];                                                       // The path may in this case also be called the 'scheme specific part'.
            return;
        }
        
        rawUri = rawUri[3 .. $];
        uint endIndex = cast(uint) rawUri.length;
        
        void setIfSmaller(in int i)
        {
            if(i != -1 && i < endIndex)
                endIndex = i;
        }
        
        setIfSmaller(cast(int) indexOf(rawUri, "/"));
        setIfSmaller(cast(int) indexOf(rawUri, "?"));
        setIfSmaller(cast(int) indexOf(rawUri, "#"));
        
        enforce(endIndex, "The authority cannot be empty!");                                // The path must be absolute, therefore the authority can not be empty.
        
        authority = toLower(rawUri[0 .. endIndex]);                                         // Both the scheme (above) and the authority are case-insensitive.
        
        rawUri = rawUri[endIndex .. $];
        if(rawUri.length <= 1)                                                              // Return when there is nothing left to parse.
            return;
        
        // At this point the raw URI that remains, will begin with either a slash, question mark or hashtag.
        
        if(rawUri[0] == '/')                                                                // The URI has a path. This code is almost identical to the lines above.
        {
            rawUri = rawUri[1 .. $];
            endIndex = cast(int) rawUri.length;
            
            setIfSmaller(cast(int) indexOf(rawUri, "?"));
            setIfSmaller(cast(int) indexOf(rawUri, "#"));
            
            rawPath = rawUri[0 .. endIndex];
            rawUri = rawUri[endIndex .. $];
            if(rawUri.length <= 1)
                return;
        }
        
        if(rawUri[0] == '?')                                                                // The URI has a query. This code is identical to the lines above.
        {
            rawUri = rawUri[1 .. $];
            endIndex = cast(int) rawUri.length;
            
            setIfSmaller(cast(int) indexOf(rawUri, "#"));
            
            rawQuery = rawUri[0 .. endIndex];
            rawUri = rawUri[endIndex .. $];
            if(rawUri.length <= 1)
                return;
        }
        
        fragment = rawUri[1 .. $];                                                          // If there is anything left, it must be the fragment.
    }
    
    this(in string scheme, in string host)
    {
        this.scheme = scheme;
        this.host = host;
    }
    
    this(in string scheme, in string host, in string path)
    {
        this.scheme = scheme;
        this.host = host;
        this.rawPath = path;
    }
    
    this(in string scheme, in string host, in string[] path)
    {
        this.scheme = scheme;
        this.host = host;
        this.path = path.dup;
    }
    
    this(in string scheme, in string username, in string password, in string host, in string path)
    {
        this.scheme = scheme;
        this.username = username;
        this.password = password;
        this.host = host;
        this.rawPath = path;
    }
    
    this(in string scheme, in string username, in string password, in string host, in string[] path)
    {
        this.scheme = scheme;
        this.username = username;
        this.password = password;
        this.host = host;
        this.path = path.dup;
    }
    
    unittest
    {
        enum URI uri1 = URI("http://dlang.org/");
        assert(uri1.scheme == "http");
        assert(uri1.authority == "dlang.org");
        assert(uri1.path == []);
        assert(uri1.query.length == 0);
        
        enum URI uri2 = URI("http://dlang.org/unittest.html");
        assert(uri2.scheme == "http");
        assert(uri2.authority == "dlang.org");
        assert(uri2.path == ["unittest.html"]);
        assert(uri2.query.length == 0);
        
        enum URI uri3 = URI("https://openid.stackexchange.com/account/login");
        assert(uri3.scheme == "https");
        assert(uri3.authority == "openid.stackexchange.com");
        assert(uri3.path == ["account", "login"]);
        assert(uri3.query.length == 0);
        
        const URI uri4 = URI("http://www.google.com/search?q=forum&sitesearch=dlang.org");
        assert(uri4.scheme == "http");
        assert(uri4.authority == "www.google.com");
        assert(uri4.path == ["search"]);
        assert(uri4.query == ["q": "forum", "sitesearch": "dlang.org"]);
        
        enum URI uri5 = URI("magnet:?xt=urn:sha1:YNCKHTQCWBTRNJIV4WNAE52SJUQCZO5C");
        assert(uri5.scheme == "magnet");
        assert(uri5.authority == "");
        assert(uri5.rawPath == "?xt=urn:sha1:YNCKHTQCWBTRNJIV4WNAE52SJUQCZO5C");
        assert(uri5.query.length == 0);
        
        enum URI uri6 = URI("ftp://user:password@about.com/Documents/The%20D%20Programming%20Language.pdf");
        assert(uri6.scheme == "ftp");
        assert(uri6.authority == "user:password@about.com");
        assert(uri6.path == ["Documents", "The%20D%20Programming%20Language.pdf"]);
        assert(uri6.query.length == 0);
        assert(uri6.host == "about.com");
        assert(uri6.port == 0);
        assert(uri6.username == "user");
        assert(uri6.password == "password");
        
        enum URI uri7 = URI("http-://anything.com");
        assert(uri7.scheme == "http-");
        
        enum URI uri8 = URI("ftp://ftp.is.co.za/rfc/rfc1808.txt");
        assert(uri8.scheme == "ftp");
        assert(uri8.authority == "ftp.is.co.za");
        assert(uri8.path == ["rfc", "rfc1808.txt"]);
        assert(uri8.query.length == 0);
        
        enum URI uri9 = URI("http://www.ietf.org/rfc/rfc2396.txt");
        assert(uri9.scheme == "http");
        assert(uri9.authority == "www.ietf.org");
        assert(uri9.path == ["rfc", "rfc2396.txt"]);
        assert(uri9.query.length == 0);
        
        const URI uri10 = URI("ldap://[2001:db8::7]/c=GB?objectClass?one");
        assert(uri10.scheme == "ldap");
        assert(uri10.authority == "[2001:db8::7]");
        assert(uri10.path == ["c=GB"]);
        assert(uri10.query == ["objectClass?one": ""]);
        assert(uri10.host == "[2001:db8::7]");
        assert(uri10.port == 0);
        assert(uri10.username == "");
        assert(uri10.password.length == 0);
        
        enum URI uri11 = URI("mailto:John.Doe@example.com");
        assert(uri11.scheme == "mailto");
        assert(uri11.authority == "");
        assert(uri11.rawPath == "John.Doe@example.com");
        assert(uri11.query.length == 0);
        
        enum URI uri12 = URI("news:comp.infosystems.www.servers.unix");
        assert(uri12.scheme == "news");
        assert(uri12.authority == "");
        assert(uri12.rawPath == "comp.infosystems.www.servers.unix");
        assert(uri12.query.length == 0);
        
        enum URI uri13 = URI("tel:+1-816-555-1212");
        assert(uri13.scheme == "tel");
        assert(uri13.authority == "");
        assert(uri13.rawPath == "+1-816-555-1212");
        assert(uri13.query.length == 0);
        
        enum URI uri14 = URI("telnet://192.0.2.16:80/");
        assert(uri14.scheme == "telnet");
        assert(uri14.authority == "192.0.2.16:80");
        assert(uri14.path == []);
        assert(uri14.query.length == 0);
        
        enum URI uri15 = URI("urn:oasis:names:specification:docbook:dtd:xml:4.1.2");
        assert(uri15.scheme == "urn");
        assert(uri15.authority == "");
        assert(uri15.path == ["oasis:names:specification:docbook:dtd:xml:4.1.2"]);
        assert(uri15.query.length == 0);
        
        const URI uri16 = URI("foo://username:password@example.com:8042/over/there/index.dtb?type=animal&name=narwhal&novalue#nose");
        assert(uri16.scheme == "foo");
        assert(uri16.authority == "username:password@example.com:8042");
        assert(uri16.rawPath == "over/there/index.dtb");
        assert(uri16.path == ["over", "there", "index.dtb"]);
        assert(uri16.rawQuery == "type=animal&name=narwhal&novalue");
        assert(uri16.query == ["type": "animal", "name": "narwhal", "novalue": ""]);
        assert(uri16.fragment == "nose");
        assert(uri16.host == "example.com");
        assert(uri16.port == 8042);
        assert(uri16.username == "username");
        assert(uri16.password == "password");
        assert(uri16.userinfo == "username:password");
        assert(uri16.query["type"] == "animal");
        assert(uri16.query["novalue"] == "");
        assert("novalue" in uri16.query);
        assert(!("nothere" in uri16.query));
        assert(uri16 == "foo://username:password@example.com:8042/over/there/index.dtb?type=animal&name=narwhal&novalue#nose");
        
        enum URI uri21 = URI("ftp://userwithoutpassword@about.com/");
        assert(uri21.scheme == "ftp");
        assert(uri21.host == "about.com");
        assert(uri21.username == "userwithoutpassword");
        assert(uri21.password.length == 0);
        assert(uri21 != "ftp://about.com/");
        
        enum URI uri22 = URI("file://localhost/etc/hosts");
        assert(uri22.scheme == "file");
        assert(uri22.host == "localhost");
        assert(uri22.path == ["etc", "hosts"]);
        
        const URI uri23 = URI("http://dlang.org/?value&value=1&value=2");
        assert(uri23.scheme == "http");
        assert(uri23.authority == "dlang.org");
        assert(uri23.path == []);
        assert(uri23.queryMulti == cast(const) ["value": ["", "1", "2"]]);  // Because of a bug (I think) the cast to const is necessary.
        assert(uri23.query["value"] == "2");
        
        URI uri;
        uri.scheme = "https";
        uri.host = "github.com";
        uri.rawPath = "aBothe/Mono-D/blob/master/MonoDevelop.DBinding/Building/ProjectBuilder.cs";
        uri.fragment = "L13";
        assert(uri == "https://github.com/aBothe/Mono-D/blob/master/MonoDevelop.DBinding/Building/ProjectBuilder.cs#L13");
        
        uri = URI();
        uri.scheme = "foo";
        uri.username = "username";
        uri.password = "password";
        uri.host = "example.com";
        uri.port = 8042;
        uri.path = ["over", "there", "index.dtb"];
        uri.query = ["type": "animal", "name": "narwhal", "novalue": ""];
        uri.fragment = "nose";
        assert(uri == URI("foo://username:password@example.com:8042/over/there/index.dtb?novalue=&type=animal&name=narwhal#nose"));
        assert(uri.query ==  ["type": "animal", "name": "narwhal", "novalue": ""]);
        assert(uri.queryMulti == cast(const) ["type": ["animal"], "name": ["narwhal"], "novalue": [""]]);
        uri.authority = "";
        assert(uri.host.length == 0);
        assert(uri.port == 0);
        assert(uri.username.length == 0);
        assert(uri.password.length == 0);
        assert(uri.rawPath == "over/there/index.dtb");
        assert(uri.rawQuery == "novalue=&type=animal&name=narwhal");
        
        uri = URI();
        uri.scheme = "https";
        uri.host = "github.com";
        uri.rawPath = "adamdruppe/misc-stuff-including-D-programming-language-web-stuff";
        assert(uri == "https://github.com/adamdruppe/misc-stuff-including-D-programming-language-web-stuff");
        uri.path = uri.path ~ ["blob", "master", "cgi.d"];
        uri.fragment = "L1070";
        assert(uri == "https://github.com/adamdruppe/misc-stuff-including-D-programming-language-web-stuff/blob/master/cgi.d#L1070");
        uri.query = ["type": "animal"];
        uri.username = "user";
        uri.password = "pass";
        uri.path = [];
        assert(uri == "https://user:pass@github.com/?type=animal#L1070");
        uri.port = 8080;
        assert(uri == "https://user:pass@github.com:8080/?type=animal#L1070");
        
        URI("http://dlang.org/");
        URI("tel:+1-816-555-1212");
        URI("ftp://userwithoutpassword@about.com/");
        URI("ftp://user:password@about.com/");
        URI("http://www.ietf.org/rfc/rfc2396.txt");
        URI("http://dlang.org/phobos/std_string.html#indexOf");
        URI("http://d.puremagic.com/issues/show_bug.cgi?id=4019");
        URI("ldap://[2001:db8::7]/");
        URI("http://website.com/?key");
        
        assertThrown(URI("-http://anything.com"));
        assertThrown(URI("5five:anything"));
        assertThrown(URI("irc"));
        assertThrown(URI("http://[an incomplete ipv6 address/path/to/file.d"));
        assertThrown(URI("http:///path/to/file.d"));
        assertThrown(URI("d"));
        assertThrown(URI("ldap://[2001:db8::7]character:8080/c=GB?objectClass?one"));
        
//      If relative URIs will be supported, these unittests should pass.
        
//      //example.org/scheme-relative/URI/with/absolute/path/to/resource.txt
//      /relative/URI/with/absolute/path/to/resource.txt
//      relative/path/to/resource.txt
//      ../../../resource.txt
//      ./resource.txt#frag01
//      resource.txt
//      #frag01
//      (empty string)
        
//        uri = URI("file:///etc/hosts");
//        assert(uri.scheme == "file");
//        assert(uri.host == "");
//        assert(uri.path == ["etc", "hosts"]);
//        
//        uri = URI("//example.org/scheme-relative/URI/with/absolute/path/to/resource.txt");
//        assert(uri.scheme == "");
//        assert(uri.host == "example.org");
//        assert(uri.rawPath == "scheme-relative/URI/with/absolute/path/to/resource.txt");
//        
//        uri = URI("/relative/URI/with/absolute/path/to/resource.txt");
//        assert(uri.scheme == "");
//        assert(uri.host == "");
//        assert(uri.rawPath == "relative/URI/with/absolute/path/to/resource.txt");
//        
//        uri = URI("relative/path/to/resource.txt");
//        assert(uri.scheme == "");
//        assert(uri.host == "");
//        assert(uri.rawPath == "relative/path/to/resource.txt");
//        
//        uri = URI("../../../resource.txt");
//        assert(uri.scheme == "");
//        assert(uri.host == "");
//        assert(uri.rawPath == "../../../resource.txt");
//        
//        uri = URI("./resource.txt#frag01");
//        assert(uri.scheme == "");
//        assert(uri.host == "");
//        assert(uri.path == [".", "resource.txt"]);
//        assert(uri.fragment == "frag01");
//        
//        uri = URI("resource.txt");
//        assert(uri.scheme == "");
//        assert(uri.host == "");
//        assert(uri.path == ["resource.txt"]);
//        
//        uri = URI("#frag01");
//        assert(uri.scheme == "");
//        assert(uri.host == "");
//        assert(uri.path == []);
//        assert(uri.fragment == "frag01");
//        
//        // According to this list, an empty string would be a valid URI reference. I'm not so sure if we should allow it.
//        // http://en.wikipedia.org/wiki/Uniform_resource_identifier#Examples_of_URI_references
//        uri = URI("");
//        assert(uri.scheme == "");
//        assert(uri.host == "");
//        assert(uri.path == []);
    }
}
