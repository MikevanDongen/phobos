module std.net.uri;

private import std.ascii;
private import std.string;
private import std.conv : to;

/**
 * @author      Mike van Dongen <dlang@mikevandongen.nl>
 */
class URI
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
        string rawAuthority = value;
        long i = std.string.indexOf(value, '@');
        if(i != -1)                                                         // Check if it contains userinfo.
        {
            string userinfo = value[0 .. i];
            value = value[i+1 .. $];
            
            i = std.string.indexOf(userinfo, ':');
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
            i = std.string.indexOf(value, ']');
            if(i == -1)
                return null; // Not sure how to handle this atm.
            host = value[0 .. i+1];
            value = value[i+1 .. $];
            ipLiteral = true;
        }
        
        i = std.string.indexOf(value, ':');
        if(i != -1)                                                         // Check if it contains a port number.
        {
            if(ipLiteral && i != 0)                                         // If it has a portnumber, it should be immediately after the IPv6 address.
                return null;
            
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
        _path = std.array.split(value, "/");
        return _rawPath = value;
    }
    
    @property const(string[]) path() const { return _path; }
    @property string[] path(string[] value)
    {
        _rawPath = std.array.join(value, "/");
        return _path = value;
    }
    
    @property string rawQuery() const { return _rawQuery; }
    @property string rawQuery(const string value)
    {
        auto pairs = std.array.split(value, "&");
        string[][string] newQuery;
        foreach(q; pairs)
        {
            auto pair = std.string.indexOf(q, "=");
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
    
    override const string toString() const
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
    
    override bool opEquals(Object b)
    {
        if(auto o = cast(URI) b)
            return 
                _path     == o._path &&
                _query    == o._query &&
                scheme    == o.scheme &&
                username  == o.username &&
                password  == o.password &&
                host      == o.host &&
                port      == o.port &&
                fragment  == o.fragment;
        return opEquals(b.toString());
    }
    
    bool opEquals(const string b) const
    {
        return toString() == b;
    }
    
    /**
     * This method parses an URI as defined in RFC 3986 (http://www.ietf.org/rfc/rfc3986.txt).
     */
    static URI parse(in string requestUri)
    {
        string rawUri = requestUri;
        URI uri = new URI;
        
        if(requestUri.length <= 1)                                          // An URI has atleast 1 alpha character and a ':'.
            return null;
        
        if(!isAlpha(rawUri[0]))                                             // The URI must start with a lower case letter.
            return null;
        
        uri.scheme = toLower(munch(rawUri, std.ascii.letters ~ std.ascii.digits ~ "+.-"));    // 'Collects' the characters that are considered to be part of the scheme.
        if(rawUri.length == 0 || rawUri[0] != ':')
            return null;
        
        if(rawUri.length < 3 || rawUri[1 .. 3] != "//")                     // If the URI doesn't continue with '//', than the remainder will be the path.
        {
            uri.rawPath = rawUri[1 .. $];                                   // The path may in this case also be called the 'scheme specific part'.
            return uri;
        }
        
        rawUri = rawUri[3 .. $];
        int endIndex = cast(int) [std.string.indexOf(rawUri, '/'),          // Because of the property 'length', the array is an unsigned long.
                        std.string.indexOf(rawUri, '?'),                    // So even when indexOf returns -1, it will get cast to 18,446,744,073,709,551,615 (2^64 − 1).
                        std.string.indexOf(rawUri, '#'),                    // I did it this way because at that moment it seemed like the easiest solution.
                        rawUri.length].sort[0];
        
        assert(endIndex != -1);                                             // If this assert ever fails, explicit casting should be used. Perhaps combined with `Math.min();`
        
        if(endIndex == 0)                                                   // The path must be absolute, therefore the authority can not be empty.
            return null;
        
        if((uri.authority = toLower(rawUri[0 .. endIndex])) is null)        // Both the scheme (above) and the authority are case-insensitive.
            return null;
        
        if(rawUri.length <= endIndex + 1)                                   // Return when there is nothing left to parse.
            return uri;
        rawUri = rawUri[endIndex .. $];
        
        // At this point the raw URI that remains, will begin with either a slash or a question mark.
        
        if(rawUri[0] == '/')                                                // The URI has a path. This code is almost identical to the lines above.
        {
            rawUri = rawUri[1 .. $];
            endIndex = cast(int) [std.string.indexOf(rawUri, '?'), 
                            std.string.indexOf(rawUri, '#'), 
                            rawUri.length].sort[0];
            assert(endIndex != -1);
            
            uri.rawPath = rawUri[0 .. endIndex];
            if(rawUri.length <= endIndex + 1)
                return uri;
            rawUri = rawUri[endIndex .. $];
        }
        
        if(rawUri[0] == '?')                                                // The URI has a query. This code is identical to the lines above.
        {
            rawUri = rawUri[1 .. $];
            endIndex = cast(int) [std.string.indexOf(rawUri, '#'), 
                            rawUri.length].sort[0];
            assert(endIndex != -1);
            
            uri.rawQuery = rawUri[0 .. endIndex];
            if(rawUri.length <= endIndex + 1)
                return uri;
            rawUri = rawUri[endIndex .. $];
        }
        
        uri.fragment = rawUri[1 .. $];                                      // If there is anything left, it must be the fragment.
        return uri;
    }
    
    unittest
    {
        const URI uri36 = URI.parse("http://dlang.org/");
        assert(uri36.scheme == "http");
        assert(uri36.authority == "dlang.org");
        assert(uri36.path == []);
        assert(uri36.query.length == 0);
        
        const URI uri37 = URI.parse("http://dlang.org/unittest.html");
        assert(uri37.scheme == "http");
        assert(uri37.authority == "dlang.org");
        assert(uri37.path == ["unittest.html"]);
        assert(uri37.query.length == 0);
        
        const URI uri38 = URI.parse("https://openid.stackexchange.com/account/login");
        assert(uri38.scheme == "https");
        assert(uri38.authority == "openid.stackexchange.com");
        assert(uri38.path == ["account", "login"]);
        assert(uri38.query.length == 0);
        
        const URI uri39 = URI.parse("http://www.google.com/search?q=forum&sitesearch=dlang.org");
        assert(uri39.scheme == "http");
        assert(uri39.authority == "www.google.com");
        assert(uri39.path == ["search"]);
        assert(uri39.query == ["q": "forum", "sitesearch": "dlang.org"]);
        
        const URI uri2 = URI.parse("magnet:?xt=urn:sha1:YNCKHTQCWBTRNJIV4WNAE52SJUQCZO5C");
        assert(uri2.scheme == "magnet");
        assert(uri2.authority == "");
        assert(uri2.rawPath == "?xt=urn:sha1:YNCKHTQCWBTRNJIV4WNAE52SJUQCZO5C");
        assert(uri2.query.length == 0);
        
        const URI uri3 = URI.parse("ftp://user:password@about.com/Documents/The%20D%20Programming%20Language.pdf");
        assert(uri3.scheme == "ftp");
        assert(uri3.authority == "user:password@about.com");
        assert(uri3.path == ["Documents", "The%20D%20Programming%20Language.pdf"]);
        assert(uri3.query.length == 0);
        assert(uri3.host == "about.com");
        assert(uri3.port == 0);
        assert(uri3.username == "user");
        assert(uri3.password == "password");
        
        const URI uri4 = URI.parse("http-://anything.com");
        assert(uri4.scheme == "http-");
        
        const URI uri5 = URI.parse("-http://anything.com");
        assert(uri5 is null);
        
        const URI uri6 = URI.parse("5five:anything");
        assert(uri6 is null);
        
        const URI uri7 = URI.parse("irc");
        assert(uri7 is null);
        
        const URI uri8 = URI.parse("ftp://ftp.is.co.za/rfc/rfc1808.txt");
        assert(uri8.scheme == "ftp");
        assert(uri8.authority == "ftp.is.co.za");
        assert(uri8.path == ["rfc", "rfc1808.txt"]);
        assert(uri8.query.length == 0);
        
        const URI uri9 = URI.parse("http://www.ietf.org/rfc/rfc2396.txt");
        assert(uri9.scheme == "http");
        assert(uri9.authority == "www.ietf.org");
        assert(uri9.path == ["rfc", "rfc2396.txt"]);
        assert(uri9.query.length == 0);
        
        const URI uri10 = URI.parse("ldap://[2001:db8::7]/c=GB?objectClass?one");
        assert(uri10.scheme == "ldap");
        assert(uri10.authority == "[2001:db8::7]");
        assert(uri10.path == ["c=GB"]);
        assert(uri10.query == ["objectClass?one": ""]);
        assert(uri10.host == "[2001:db8::7]");
        assert(uri10.port == 0);
        assert(uri10.username == "");
        assert(uri10.password.length == 0);
        
        const URI uri11 = URI.parse("mailto:John.Doe@example.com");
        assert(uri11.scheme == "mailto");
        assert(uri11.authority == "");
        assert(uri11.rawPath == "John.Doe@example.com");
        assert(uri11.query.length == 0);
        
        const URI uri12 = URI.parse("news:comp.infosystems.www.servers.unix");
        assert(uri12.scheme == "news");
        assert(uri12.authority == "");
        assert(uri12.rawPath == "comp.infosystems.www.servers.unix");
        assert(uri12.query.length == 0);
        
        const URI uri13 = URI.parse("tel:+1-816-555-1212");
        assert(uri13.scheme == "tel");
        assert(uri13.authority == "");
        assert(uri13.rawPath == "+1-816-555-1212");
        assert(uri13.query.length == 0);
        
        const URI uri14 = URI.parse("telnet://192.0.2.16:80/");
        assert(uri14.scheme == "telnet");
        assert(uri14.authority == "192.0.2.16:80");
        assert(uri14.path == []);
        assert(uri14.query.length == 0);
        
        const URI uri15 = URI.parse("urn:oasis:names:specification:docbook:dtd:xml:4.1.2");
        assert(uri15.scheme == "urn");
        assert(uri15.authority == "");
        assert(uri15.path == ["oasis:names:specification:docbook:dtd:xml:4.1.2"]);
        assert(uri15.query.length == 0);
        
        const URI uri21 = URI.parse("foo://username:password@example.com:8042/over/there/index.dtb?type=animal&name=narwhal&novalue#nose");
        assert(uri21.scheme == "foo");
        assert(uri21.authority == "username:password@example.com:8042");
        assert(uri21.rawPath == "over/there/index.dtb");
        assert(uri21.path == ["over", "there", "index.dtb"]);
        assert(uri21.rawQuery == "type=animal&name=narwhal&novalue");
        assert(uri21.query == ["type": "animal", "name": "narwhal", "novalue": ""]);
        assert(uri21.fragment == "nose");
        assert(uri21.host == "example.com");
        assert(uri21.port == 8042);
        assert(uri21.username == "username");
        assert(uri21.password == "password");
        assert(uri21.userinfo == "username:password");
        assert(uri21.query["type"] == "animal");
        assert(uri21.query["novalue"] == "");
        assert("novalue" in uri21.query);
        assert(!("nothere" in uri21.query));
        assert(uri21 == "foo://username:password@example.com:8042/over/there/index.dtb?type=animal&name=narwhal&novalue#nose");
        
        const URI uri16 = URI.parse("http://[an incomplete ipv6 address/path/to/file.d");
        assert(uri16 is null);
        
        const URI uri17 = URI.parse("http:///path/to/file.d");
        assert(uri17 is null);
        
        const URI uri18 = URI.parse("d");
        assert(uri18 is null);
        
        const URI uri19 = URI.parse("ldap://[2001:db8::7]character:8080/c=GB?objectClass?one");
        assert(uri19 is null);
        
        const URI uri20 = URI.parse("ftp://userwithoutpassword@about.com/");
        assert(uri20.scheme == "ftp");
        assert(uri20.host == "about.com");
        assert(uri20.username == "userwithoutpassword");
        assert(uri20.password.length == 0);
        assert(uri20 != "ftp://about.com/");
        assert(uri20 != new ForComparison());
        
        const URI uri22 = URI.parse("file://localhost/etc/hosts");
        assert(uri22.scheme == "file");
        assert(uri22.host == "localhost");
        assert(uri22.path == ["etc", "hosts"]);
        
        const URI uri23 = URI.parse("http://dlang.org/?value&value=1&value=2");
        assert(uri23.scheme == "http");
        assert(uri23.authority == "dlang.org");
        assert(uri23.path == []);
        assert(uri23.queryMulti == cast(const) ["value": ["", "1", "2"]]);  // Because of a bug (I think) the cast to const is necessary.
        assert(uri23.query["value"] == "2");
        
        URI uri = new URI();
        uri.scheme = "https";
        uri.host = "github.com";
        uri.rawPath = "aBothe/Mono-D/blob/master/MonoDevelop.DBinding/Building/ProjectBuilder.cs";
        uri.fragment = "L13";
        assert(uri == "https://github.com/aBothe/Mono-D/blob/master/MonoDevelop.DBinding/Building/ProjectBuilder.cs#L13");
        
        uri = new URI();
        uri.scheme = "foo";
        uri.username = "username";
        uri.password = "password";
        uri.host = "example.com";
        uri.port = 8042;
        uri.path = ["over", "there", "index.dtb"];
        uri.query = ["type": "animal", "name": "narwhal", "novalue": ""];
        uri.fragment = "nose";
        assert(uri == URI.parse("foo://username:password@example.com:8042/over/there/index.dtb?novalue=&type=animal&name=narwhal#nose"));
        
        uri = new URI();
        uri.scheme = "https";
        uri.host = "github.com";
        uri.rawPath = "adamdruppe/misc-stuff-including-D-programming-language-web-stuff";
        assert(uri == "https://github.com/adamdruppe/misc-stuff-including-D-programming-language-web-stuff");
        uri.path = uri.path ~ ["blob", "master", "cgi.d"];
        uri.fragment = "L1070";
        assert(uri == "https://github.com/adamdruppe/misc-stuff-including-D-programming-language-web-stuff/blob/master/cgi.d#L1070");
        
//      If relative URIs will be supported, these unittests should pass.
        
//      //example.org/scheme-relative/URI/with/absolute/path/to/resource.txt
//      /relative/URI/with/absolute/path/to/resource.txt
//      relative/path/to/resource.txt
//      ../../../resource.txt
//      ./resource.txt#frag01
//      resource.txt
//      #frag01
//      (empty string)
        
//        uri = URI.parse("file:///etc/hosts");
//        assert(uri.scheme == "file");
//        assert(uri.host == "");
//        assert(uri.path == ["etc", "hosts"]);
//        
//        uri = URI.parse("//example.org/scheme-relative/URI/with/absolute/path/to/resource.txt");
//        assert(uri.scheme == "");
//        assert(uri.host == "example.org");
//        assert(uri.rawPath == "scheme-relative/URI/with/absolute/path/to/resource.txt");
//        
//        uri = URI.parse("/relative/URI/with/absolute/path/to/resource.txt");
//        assert(uri.scheme == "");
//        assert(uri.host == "");
//        assert(uri.rawPath == "relative/URI/with/absolute/path/to/resource.txt");
//        
//        uri = URI.parse("relative/path/to/resource.txt");
//        assert(uri.scheme == "");
//        assert(uri.host == "");
//        assert(uri.rawPath == "relative/path/to/resource.txt");
//        
//        uri = URI.parse("../../../resource.txt");
//        assert(uri.scheme == "");
//        assert(uri.host == "");
//        assert(uri.rawPath == "../../../resource.txt");
//        
//        uri = URI.parse("./resource.txt#frag01");
//        assert(uri.scheme == "");
//        assert(uri.host == "");
//        assert(uri.path == [".", "resource.txt"]);
//        assert(uri.fragment == "frag01");
//        
//        uri = URI.parse("resource.txt");
//        assert(uri.scheme == "");
//        assert(uri.host == "");
//        assert(uri.path == ["resource.txt"]);
//        
//        uri = URI.parse("#frag01");
//        assert(uri.scheme == "");
//        assert(uri.host == "");
//        assert(uri.path == []);
//        assert(uri.fragment == "frag01");
//        
//        // According to this list, an empty string would be a valid URI reference. I'm not so sure if we should allow it.
//        // http://en.wikipedia.org/wiki/Uniform_resource_identifier#Examples_of_URI_references
//        uri = URI.parse("");
//        assert(uri.scheme == "");
//        assert(uri.host == "");
//        assert(uri.path == []);
    }
}

version(unittest)
{
    class ForComparison
    {
    }
}
