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
    
    @property string authority()
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
    
    @property string rawPath() { return _rawPath; }
    @property string rawPath(string value)
    {
        _path = std.array.split(value, "/");
        return _rawPath = value;
    }
    
    @property string[] path() { return _path; }
    @property string[] path(string[] value)
    {
        _rawPath = std.array.join(value, "/");
        return _path = value;
    }
    
    @property string rawQuery() { return _rawQuery; }
    @property string rawQuery(string value)
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
    
    @property string[string] query()
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
    
    @property string[][string] queryMulti() { return _query; }
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
    
    @property string userinfo()
    {
        string userinfo = username;
        if(username.length != 0 && password.length != 0)
            userinfo ~= ":" ~ password;
        return userinfo;
    }
    
    override string toString()
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
    
    bool opEquals(string b)
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
        URI uri;
        
        uri = URI.parse("http://dlang.org/");
        assert(uri.scheme == "http");
        assert(uri.authority == "dlang.org");
        assert(uri.path == []);
        assert(uri.query.length == 0);
        
        uri = URI.parse("http://dlang.org/unittest.html");
        assert(uri.scheme == "http");
        assert(uri.authority == "dlang.org");
        assert(uri.path == ["unittest.html"]);
        assert(uri.query.length == 0);
        
        uri = URI.parse("https://openid.stackexchange.com/account/login");
        assert(uri.scheme == "https");
        assert(uri.authority == "openid.stackexchange.com");
        assert(uri.path == ["account", "login"]);
        assert(uri.query.length == 0);
        
        uri = URI.parse("http://www.google.com/search?q=forum&sitesearch=dlang.org");
        assert(uri.scheme == "http");
        assert(uri.authority == "www.google.com");
        assert(uri.path == ["search"]);
        assert(uri.query == ["q": "forum", "sitesearch": "dlang.org"]);
        
        uri = URI.parse("magnet:?xt=urn:sha1:YNCKHTQCWBTRNJIV4WNAE52SJUQCZO5C");
        assert(uri.scheme == "magnet");
        assert(uri.authority == "");
        assert(uri.rawPath == "?xt=urn:sha1:YNCKHTQCWBTRNJIV4WNAE52SJUQCZO5C");
        assert(uri.query.length == 0);
        
        uri = URI.parse("ftp://user:password@about.com/Documents/The%20D%20Programming%20Language.pdf");
        assert(uri.scheme == "ftp");
        assert(uri.authority == "user:password@about.com");
        assert(uri.path == ["Documents", "The%20D%20Programming%20Language.pdf"]);
        assert(uri.query.length == 0);
        assert(uri.host == "about.com");
        assert(uri.port == 0);
        assert(uri.username == "user");
        assert(uri.password == "password");
        
        uri = URI.parse("http-://anything.com");
        assert(uri.scheme == "http-");
        
        uri = URI.parse("-http://anything.com");
        assert(uri is null);
        
        uri = URI.parse("5five:anything");
        assert(uri is null);
        
        uri = URI.parse("irc");
        assert(uri is null);
        
        uri = URI.parse("ftp://ftp.is.co.za/rfc/rfc1808.txt");
        assert(uri.scheme == "ftp");
        assert(uri.authority == "ftp.is.co.za");
        assert(uri.path == ["rfc", "rfc1808.txt"]);
        assert(uri.query.length == 0);
        
        uri = URI.parse("http://www.ietf.org/rfc/rfc2396.txt");
        assert(uri.scheme == "http");
        assert(uri.authority == "www.ietf.org");
        assert(uri.path == ["rfc", "rfc2396.txt"]);
        assert(uri.query.length == 0);
        
        uri = URI.parse("ldap://[2001:db8::7]/c=GB?objectClass?one");
        assert(uri.scheme == "ldap");
        assert(uri.authority == "[2001:db8::7]");
        assert(uri.path == ["c=GB"]);
        assert(uri.query == ["objectClass?one": ""]);
        assert(uri.host == "[2001:db8::7]");
        assert(uri.port == 0);
        assert(uri.username == "");
        assert(uri.password == "");
        
        uri = URI.parse("mailto:John.Doe@example.com");
        assert(uri.scheme == "mailto");
        assert(uri.authority == "");
        assert(uri.rawPath == "John.Doe@example.com");
        assert(uri.query.length == 0);
        
        uri = URI.parse("news:comp.infosystems.www.servers.unix");
        assert(uri.scheme == "news");
        assert(uri.authority == "");
        assert(uri.rawPath == "comp.infosystems.www.servers.unix");
        assert(uri.query.length == 0);
        
        uri = URI.parse("tel:+1-816-555-1212");
        assert(uri.scheme == "tel");
        assert(uri.authority == "");
        assert(uri.rawPath == "+1-816-555-1212");
        assert(uri.query.length == 0);
        
        uri = URI.parse("telnet://192.0.2.16:80/");
        assert(uri.scheme == "telnet");
        assert(uri.authority == "192.0.2.16:80");
        assert(uri.path == []);
        assert(uri.query.length == 0);
        
        uri = URI.parse("urn:oasis:names:specification:docbook:dtd:xml:4.1.2");
        assert(uri.scheme == "urn");
        assert(uri.authority == "");
        assert(uri.path == ["oasis:names:specification:docbook:dtd:xml:4.1.2"]);
        assert(uri.query.length == 0);
        
        uri = URI.parse("foo://username:password@example.com:8042/over/there/index.dtb?type=animal&name=narwhal&novalue#nose");
        assert(uri.scheme == "foo");
        assert(uri.authority == "username:password@example.com:8042");
        assert(uri.rawPath == "over/there/index.dtb");
        assert(uri.path == ["over", "there", "index.dtb"]);
        assert(uri.rawQuery == "type=animal&name=narwhal&novalue");
        assert(uri.query == ["type": "animal", "name": "narwhal", "novalue": ""]);
        assert(uri.fragment == "nose");
        assert(uri.host == "example.com");
        assert(uri.port == 8042);
        assert(uri.username == "username");
        assert(uri.password == "password");
        assert(uri.userinfo == "username:password");
        assert(uri.query["type"] == "animal");
        assert(uri.query["novalue"] == "");
        assert("novalue" in uri.query);
        assert(!("nothere" in uri.query));
        assert(uri == "foo://username:password@example.com:8042/over/there/index.dtb?type=animal&name=narwhal&novalue#nose");
        
        uri = URI.parse("http://dlang.org/?value&value=1&value=2");
        assert(uri.scheme == "http");
        assert(uri.authority == "dlang.org");
        assert(uri.path == []);
        assert(uri.queryMulti == ["value": ["", "1", "2"]]);
        assert(uri.query["value"] == "2");
        
        uri = new URI();
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
        
        uri = URI.parse("http://[an incomplete ipv6 address/path/to/file.d");
        assert(uri is null);
        
        uri = URI.parse("http:///path/to/file.d");
        assert(uri is null);
        
        uri = URI.parse("d");
        assert(uri is null);
        
        uri = URI.parse("ldap://[2001:db8::7]character:8080/c=GB?objectClass?one");
        assert(uri is null);
        
        uri = URI.parse("ftp://userwithoutpassword@about.com/");
        assert(uri.scheme == "ftp");
        assert(uri.host == "about.com");
        assert(uri.username == "userwithoutpassword");
        assert(uri.password == uri.password.init);
        assert(uri != "ftp://about.com/");
        assert(uri != new ForComparison());
    }
}

version(unittest)
{
    class ForComparison
    {
    }
}
