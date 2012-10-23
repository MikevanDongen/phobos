// Written in the D programming language.

/**
 * Encode and decode Uniform Resource Identifiers (URIs).
 * URIs are used in internet transfer protocols.
 * Valid URI characters consist of letters, digits,
 * and the characters $(B ;/?:@&amp;=+$,-_.!~*'())
 * Reserved URI characters are $(B ;/?:@&amp;=+$,)
 * Escape sequences consist of $(B %) followed by two hex digits.
 *
 * See_Also:
 *  $(LINK2 http://www.ietf.org/rfc/rfc3986.txt, RFC 3986)<br>
 *  $(LINK2 http://en.wikipedia.org/wiki/Uniform_resource_identifier, Wikipedia)
 * Macros:
 *  WIKI = Phobos/StdUri
 *
 * Copyright: Copyright Digital Mars 2000 - 2009.
 * License:   <a href="http://www.boost.org/LICENSE_1_0.txt">Boost License 1.0</a>.
 * Authors:   $(WEB digitalmars.com, Walter Bright)
 * Source:    $(PHOBOSSRC std/_uri.d)
 */
/*          Copyright Digital Mars 2000 - 2009.
 * Distributed under the Boost Software License, Version 1.0.
 *    (See accompanying file LICENSE_1_0.txt or copy at
 *          http://www.boost.org/LICENSE_1_0.txt)
 */
module std.uri;

//debug=uri;        // uncomment to turn on debugging printf's

/* ====================== URI Functions ================ */

private import std.ascii;
private import std.c.stdlib;
private import std.utf;
private import std.stdio;
private import std.string;
import std.exception;

class URIerror : Error
{
    this()
    {
    super("URI error");
    }
}

enum
{
    URI_Alpha = 1,
    URI_Reserved = 2,
    URI_Mark = 4,
    URI_Digit = 8,
    URI_Hash = 0x10,        // '#'
}

immutable char[16] hex2ascii = "0123456789ABCDEF";

__gshared ubyte[128] uri_flags;       // indexed by character

shared static this()
{
    // Initialize uri_flags[]

    static void helper(immutable char[] p, uint flags)
    {   int i;

    for (i = 0; i < p.length; i++)
        uri_flags[p[i]] |= flags;
    }

    uri_flags['#'] |= URI_Hash;

    for (int i = 'A'; i <= 'Z'; i++)
    {   uri_flags[i] |= URI_Alpha;
    uri_flags[i + 0x20] |= URI_Alpha;   // lowercase letters
    }
    helper("0123456789", URI_Digit);
    helper(";/?:@&=+$,", URI_Reserved);
    helper("-_.!~*'()",  URI_Mark);
}


private string URI_Encode(dstring string, uint unescapedSet)
{
    uint j;
    uint k;
    dchar V;
    dchar C;

    // result buffer
    char[50] buffer = void;
    char* R;
    uint Rlen;
    uint Rsize; // alloc'd size

    auto len = string.length;

    R = buffer.ptr;
    Rsize = buffer.length;
    Rlen = 0;

    for (k = 0; k != len; k++)
    {
    C = string[k];
    // if (C in unescapedSet)
    if (C < uri_flags.length && uri_flags[C] & unescapedSet)
    {
        if (Rlen == Rsize)
        {   char* R2;

        Rsize *= 2;
        if (Rsize > 1024)
            R2 = (new char[Rsize]).ptr;
        else
        {   R2 = cast(char *)alloca(Rsize * char.sizeof);
            if (!R2)
            goto LthrowURIerror;
        }
        R2[0..Rlen] = R[0..Rlen];
        R = R2;
        }
        R[Rlen] = cast(char)C;
        Rlen++;
    }
    else
    {   char[6] Octet;
        uint L;

        V = C;

        // Transform V into octets
        if (V <= 0x7F)
        {
        Octet[0] = cast(char) V;
        L = 1;
        }
        else if (V <= 0x7FF)
        {
        Octet[0] = cast(char)(0xC0 | (V >> 6));
        Octet[1] = cast(char)(0x80 | (V & 0x3F));
        L = 2;
        }
        else if (V <= 0xFFFF)
        {
        Octet[0] = cast(char)(0xE0 | (V >> 12));
        Octet[1] = cast(char)(0x80 | ((V >> 6) & 0x3F));
        Octet[2] = cast(char)(0x80 | (V & 0x3F));
        L = 3;
        }
        else if (V <= 0x1FFFFF)
        {
        Octet[0] = cast(char)(0xF0 | (V >> 18));
        Octet[1] = cast(char)(0x80 | ((V >> 12) & 0x3F));
        Octet[2] = cast(char)(0x80 | ((V >> 6) & 0x3F));
        Octet[3] = cast(char)(0x80 | (V & 0x3F));
        L = 4;
        }
    /+
        else if (V <= 0x3FFFFFF)
        {
        Octet[0] = cast(char)(0xF8 | (V >> 24));
        Octet[1] = cast(char)(0x80 | ((V >> 18) & 0x3F));
        Octet[2] = cast(char)(0x80 | ((V >> 12) & 0x3F));
        Octet[3] = cast(char)(0x80 | ((V >> 6) & 0x3F));
        Octet[4] = cast(char)(0x80 | (V & 0x3F));
        L = 5;
        }
        else if (V <= 0x7FFFFFFF)
        {
        Octet[0] = cast(char)(0xFC | (V >> 30));
        Octet[1] = cast(char)(0x80 | ((V >> 24) & 0x3F));
        Octet[2] = cast(char)(0x80 | ((V >> 18) & 0x3F));
        Octet[3] = cast(char)(0x80 | ((V >> 12) & 0x3F));
        Octet[4] = cast(char)(0x80 | ((V >> 6) & 0x3F));
        Octet[5] = cast(char)(0x80 | (V & 0x3F));
        L = 6;
        }
     +/
        else
        {   goto LthrowURIerror;        // undefined UTF-32 code
        }

        if (Rlen + L * 3 > Rsize)
        {   char *R2;

        Rsize = 2 * (Rlen + L * 3);
        if (Rsize > 1024)
            R2 = (new char[Rsize]).ptr;
        else
        {   R2 = cast(char *)alloca(Rsize * char.sizeof);
            if (!R2)
            goto LthrowURIerror;
        }
        R2[0..Rlen] = R[0..Rlen];
        R = R2;
        }

        for (j = 0; j < L; j++)
        {
        R[Rlen] = '%';
        R[Rlen + 1] = hex2ascii[Octet[j] >> 4];
        R[Rlen + 2] = hex2ascii[Octet[j] & 15];

        Rlen += 3;
        }
    }
    }

    return R[0..Rlen].idup;

LthrowURIerror:
    throw new URIerror();
}

uint ascii2hex(dchar c)
{
    return (c <= '9') ? c - '0' :
       (c <= 'F') ? c - 'A' + 10 :
            c - 'a' + 10;
}

private dstring URI_Decode(string string, uint reservedSet)
{
    uint j;
    uint k;
    uint V;
    dchar C;

    //printf("URI_Decode('%.*s')\n", string);

    // Result array, allocated on stack
    dchar* R;
    uint Rlen;

    auto len = string.length;
    auto s = string.ptr;

    // Preallocate result buffer R guaranteed to be large enough for result
    auto Rsize = len;
    if (Rsize > 1024 / dchar.sizeof)
    R = (new dchar[Rsize]).ptr;
    else
    {   R = cast(dchar *)alloca(Rsize * dchar.sizeof);
    if (!R)
        goto LthrowURIerror;
    }
    Rlen = 0;

    for (k = 0; k != len; k++)
    {   char B;
    uint start;

    C = s[k];
    if (C != '%')
    {   R[Rlen] = C;
        Rlen++;
        continue;
    }
    start = k;
    if (k + 2 >= len)
        goto LthrowURIerror;
    if (!isHexDigit(s[k + 1]) || !isHexDigit(s[k + 2]))
        goto LthrowURIerror;
    B = cast(char)((ascii2hex(s[k + 1]) << 4) + ascii2hex(s[k + 2]));
    k += 2;
    if ((B & 0x80) == 0)
    {
        C = B;
    }
    else
    {   uint n;

        for (n = 1; ; n++)
        {
        if (n > 4)
            goto LthrowURIerror;
        if (((B << n) & 0x80) == 0)
        {
            if (n == 1)
            goto LthrowURIerror;
            break;
        }
        }

        // Pick off (7 - n) significant bits of B from first byte of octet
        V = B & ((1 << (7 - n)) - 1);   // (!!!)

        if (k + (3 * (n - 1)) >= len)
        goto LthrowURIerror;
        for (j = 1; j != n; j++)
        {
        k++;
        if (s[k] != '%')
            goto LthrowURIerror;
        if (!isHexDigit(s[k + 1]) || !isHexDigit(s[k + 2]))
            goto LthrowURIerror;
        B = cast(char)((ascii2hex(s[k + 1]) << 4) + ascii2hex(s[k + 2]));
        if ((B & 0xC0) != 0x80)
            goto LthrowURIerror;
        k += 2;
        V = (V << 6) | (B & 0x3F);
        }
        if (V > 0x10FFFF)
        goto LthrowURIerror;
        C = V;
    }
    if (C < uri_flags.length && uri_flags[C] & reservedSet)
    {
        // R ~= s[start .. k + 1];
        int width = (k + 1) - start;
        for (int ii = 0; ii < width; ii++)
        R[Rlen + ii] = s[start + ii];
        Rlen += width;
    }
    else
    {
        R[Rlen] = C;
        Rlen++;
    }
    }
    assert(Rlen <= Rsize);  // enforce our preallocation size guarantee

    // Copy array on stack to array in memory
    return R[0..Rlen].idup;


LthrowURIerror:
    throw new URIerror();
}

/*************************************
 * Decodes the URI string encodedURI into a UTF-8 string and returns it.
 * Escape sequences that resolve to reserved URI characters are not replaced.
 * Escape sequences that resolve to the '#' character are not replaced.
 */

string decode(string encodedURI)
{
    auto s = URI_Decode(encodedURI, URI_Reserved | URI_Hash);
    return std.utf.toUTF8(s);
}

/*******************************
 * Decodes the URI string encodedURI into a UTF-8 string and returns it. All
 * escape sequences are decoded.
 */

string decodeComponent(string encodedURIComponent)
{
    auto s = URI_Decode(encodedURIComponent, 0);
    return std.utf.toUTF8(s);
}

/*****************************
 * Encodes the UTF-8 string uri into a URI and returns that URI. Any character
 * not a valid URI character is escaped. The '#' character is not escaped.
 */

string encode(string uri)
{
    auto s = std.utf.toUTF32(uri);
    return URI_Encode(s, URI_Reserved | URI_Hash | URI_Alpha | URI_Digit | URI_Mark);
}

/********************************
 * Encodes the UTF-8 string uriComponent into a URI and returns that URI.
 * Any character not a letter, digit, or one of -_.!~*'() is escaped.
 */

string encodeComponent(string uriComponent)
{
    auto s = std.utf.toUTF32(uriComponent);
    return URI_Encode(s, URI_Alpha | URI_Digit | URI_Mark);
}

/***************************
 * Does string s[] start with a URL?
 * Returns:
 *  -1    it does not
 *  len  it does, and s[0..len] is the slice of s[] that is that URL
 */

size_t uriLength(string s)
{
    /* Must start with one of:
     *  http://
     *  https://
     *  www.
     */

    size_t i;

    if (s.length <= 4)
    goto Lno;

    //writefln("isURL(%s)", s);
    if (s.length > 7 && std.string.icmp(s[0 .. 7], "http://") == 0)
    i = 7;
    else if (s.length > 8 && std.string.icmp(s[0 .. 8], "https://") == 0)
    i = 8;
//    if (icmp(s[0 .. 4], "www.") == 0)
//  i = 4;
    else
    goto Lno;

    size_t lastdot;
    for (; i < s.length; i++)
    {
    auto c = s[i];
    if (isAlphaNum(c))
        continue;
    if (c == '-' || c == '_' || c == '?' ||
        c == '=' || c == '%' || c == '&' ||
        c == '/' || c == '+' || c == '#' ||
        c == '~' || c == '$')
        continue;
    if (c == '.')
    {
        lastdot = i;
        continue;
    }
    break;
    }
    //if (!lastdot || (i - lastdot != 3 && i - lastdot != 4))
    if (!lastdot)
    goto Lno;

    return i;

Lno:
    return -1;
}

/***************************
 * Does string s[] start with an email address?
 * Returns:
 *  -1    it does not
 *  len   it does, and s[0..i] is the slice of s[] that is that email address
 * References:
 *  RFC2822
 */
size_t emailLength(string s)
{   size_t i;

    if (!isAlpha(s[0]))
    goto Lno;

    for (i = 1; 1; i++)
    {
    if (i == s.length)
        goto Lno;
    auto c = s[i];
    if (isAlphaNum(c))
        continue;
    if (c == '-' || c == '_' || c == '.')
        continue;
    if (c != '@')
        goto Lno;
    i++;
    break;
    }
    //writefln("test1 '%s'", s[0 .. i]);

    /* Now do the part past the '@'
     */
    size_t lastdot;
    for (; i < s.length; i++)
    {
    auto c = s[i];
    if (isAlphaNum(c))
        continue;
    if (c == '-' || c == '_')
        continue;
    if (c == '.')
    {
        lastdot = i;
        continue;
    }
    break;
    }
    if (!lastdot || (i - lastdot != 3 && i - lastdot != 4))
    goto Lno;

    return i;

Lno:
    return -1;
}


unittest
{
    debug(uri) printf("uri.encodeURI.unittest\n");

    string s = "http://www.digitalmars.com/~fred/fred's RX.html#foo";
    string t = "http://www.digitalmars.com/~fred/fred's%20RX.html#foo";

    auto r = encode(s);
    debug(uri) printf("r = '%.*s'\n", r);
    assert(r == t);
    r = decode(t);
    debug(uri) printf("r = '%.*s'\n", r);
    assert(r == s);

    r = encode( decode("%E3%81%82%E3%81%82") );
    assert(r == "%E3%81%82%E3%81%82");

    r = encodeComponent("c++");
    //printf("r = '%.*s'\n", r);
    assert(r == "c%2B%2B");

    auto str = new char[10_000_000];
    str[] = 'A';
    r = encodeComponent(assumeUnique(str));
    foreach (char c; r)
    assert(c == 'A');

    r = decode("%41%42%43");
    debug(uri) writefln(r);
}

/**
 * @author		Mike van Dongen <dlang@mikevandongen.nl>
 */
class Uri
{
	string scheme;
	string authority;
	string path;
	string query;
	
	/**
	 * This method parses an URI as defined in RFC 3986 (http://www.ietf.org/rfc/rfc3986.txt).
	 */
	static Uri parse(in string requestUri)
	{
		string rawUri = requestUri;
		Uri uri = new Uri;
		
		if(requestUri.length <= 1)
			return uri;
		
		if(!isAlpha(rawUri[0]))											// The URI must start with a lower case letter.
			return null;
		
		uri.scheme = toLower(munch(rawUri, std.ascii.letters ~ std.ascii.digits ~ "+.-"));	// 'Collects' the characters that are considered to be part of the scheme.
		if(rawUri.length == 0 || rawUri[0] != ':')
			return null;
		
		if(rawUri.length < 3 || rawUri[1 .. 3] != "//")					// If the URI doesn't continue with '//', than the remainder will be the path.
		{
			uri.path = rawUri[1 .. $];									// The path may in this case also be called the 'scheme specific part'.
			return uri;
		}
		
		rawUri = rawUri[3 .. $];
		int endIndex = cast(int) [std.string.indexOf(rawUri, '/'), 		// Because of the property 'length', the array is an unsigned long.
						std.string.indexOf(rawUri, '?'), 				// So even when indexOf returns -1, it will get cast to 18,446,744,073,709,551,615 (2^64 − 1).
						rawUri.length].sort[0];							// I did it this way because at that moment it seemed like the easiest solution.
		
		assert(endIndex != -1);											// If this assert ever fails, explicit casting should be used. Perhaps combined with `Math.min();`
		
		if(endIndex == 0)												// The path must be absolute, therefore the authority can not be empty.
			return null;
		
		uri.authority = toLower(rawUri[0 .. endIndex]);					// Both the scheme (above) and the authority are case-insensitive.
		if(rawUri.length <= endIndex + 1)								// Return when there is nothing left to parse.
			return uri;
		rawUri = rawUri[endIndex .. $];
		
		// At this point the raw URI that remains, will begin with either a slash or a question mark.
		
		if(rawUri[0] == '/')											// The URI has a path. This code is almost identical to the lines above.
		{
			rawUri = rawUri[1 .. $];
			endIndex = cast(int) [std.string.indexOf(rawUri, '?'), 
							rawUri.length].sort[0];
			assert(endIndex != -1);
			
			uri.path = rawUri[0 .. endIndex];
			if(rawUri.length <= endIndex + 1)
				return uri;
			rawUri = rawUri[endIndex .. $];
		}
		
		uri.query = rawUri[1 .. $];										// If there is anything left, it must be the query.
		return uri;
	}
	
	unittest
	{
		Uri uri;
		
		uri = Uri.parse("http://dlang.org/");
		assert(uri.scheme == "http");
		assert(uri.authority == "dlang.org");
		assert(uri.path == "");
		assert(uri.query == "");
		
		uri = Uri.parse("http://dlang.org/unittest.html");
		assert(uri.scheme == "http");
		assert(uri.authority == "dlang.org");
		assert(uri.path == "unittest.html");
		assert(uri.query == "");
		
		uri = Uri.parse("https://openid.stackexchange.com/account/login");
		assert(uri.scheme == "https");
		assert(uri.authority == "openid.stackexchange.com");
		assert(uri.path == "account/login");
		assert(uri.query == "");
		
		uri = Uri.parse("http://www.google.com/search?q=forum&sitesearch=dlang.org");
		assert(uri.scheme == "http");
		assert(uri.authority == "www.google.com");
		assert(uri.path == "search");
		assert(uri.query == "q=forum&sitesearch=dlang.org");
		
		uri = Uri.parse("magnet:?xt=urn:sha1:YNCKHTQCWBTRNJIV4WNAE52SJUQCZO5C");
		assert(uri.scheme == "magnet");
		assert(uri.authority == "");
		assert(uri.path == "?xt=urn:sha1:YNCKHTQCWBTRNJIV4WNAE52SJUQCZO5C");
		assert(uri.query == "");
		
		uri = Uri.parse("ftp://user:password@about.com/Documents/The%20D%20Programming%20Language.pdf");
		assert(uri.scheme == "ftp");
		assert(uri.authority == "user:password@about.com");
		assert(uri.path == "Documents/The%20D%20Programming%20Language.pdf");
		assert(uri.query == "");
		
		uri = Uri.parse("http-://anything.com");
		assert(uri.scheme == "http-");
		
		uri = Uri.parse("-http://anything.com");
		assert(uri is null);
		
		uri = Uri.parse("5five:anything");
		assert(uri is null);
		
		uri = Uri.parse("irc");
		assert(uri is null);
		
		uri = Uri.parse("ftp://ftp.is.co.za/rfc/rfc1808.txt");
		assert(uri.scheme == "ftp");
		assert(uri.authority == "ftp.is.co.za");
		assert(uri.path == "rfc/rfc1808.txt");
		assert(uri.query == "");
		
		uri = Uri.parse("http://www.ietf.org/rfc/rfc2396.txt");
		assert(uri.scheme == "http");
		assert(uri.authority == "www.ietf.org");
		assert(uri.path == "rfc/rfc2396.txt");
		assert(uri.query == "");
		
		uri = Uri.parse("ldap://[2001:db8::7]/c=GB?objectClass?one");
		assert(uri.scheme == "ldap");
		assert(uri.authority == "[2001:db8::7]");
		assert(uri.path == "c=GB");
		assert(uri.query == "objectClass?one");
		
		uri = Uri.parse("mailto:John.Doe@example.com");
		assert(uri.scheme == "mailto");
		assert(uri.authority == "");
		assert(uri.path == "John.Doe@example.com");
		assert(uri.query == "");
		
		uri = Uri.parse("news:comp.infosystems.www.servers.unix");
		assert(uri.scheme == "news");
		assert(uri.authority == "");
		assert(uri.path == "comp.infosystems.www.servers.unix");
		assert(uri.query == "");
		
		uri = Uri.parse("tel:+1-816-555-1212");
		assert(uri.scheme == "tel");
		assert(uri.authority == "");
		assert(uri.path == "+1-816-555-1212");
		assert(uri.query == "");
		
		uri = Uri.parse("telnet://192.0.2.16:80/");
		assert(uri.scheme == "telnet");
		assert(uri.authority == "192.0.2.16:80");
		assert(uri.path == "");
		assert(uri.query == "");
		
		uri = Uri.parse("urn:oasis:names:specification:docbook:dtd:xml:4.1.2");
		assert(uri.scheme == "urn");
		assert(uri.authority == "");
		assert(uri.path == "oasis:names:specification:docbook:dtd:xml:4.1.2");
		assert(uri.query == "");
	}
}
