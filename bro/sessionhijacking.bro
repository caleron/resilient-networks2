# based on this bro script scaffold: https://www.bro.org/bro-workshop-2011/exercises/advanced-http/reuse2.bro

module HTTP;

export {

    # We track the cookie inside the HTTP state of the connection.
    redef record Info += {
        cookie: string &log &optional;
    };
}

const twitter_cookie_keys = set("_twitter_sess", "auth_token");


type CookieData: record
{
    ip: addr;           		## IP address of the user.
    user_agent: string;     		## User-Agent header.
    timestamp: time;       	 	## Last time we saw the cookie from this user.
    timestamp_readable: string;        	## Last time we saw the cookie from this user
};

global cookies: table[string] of CookieData;


# Create a unique user session identifier based on the relevant cookie keys.
# Return the empty string if the sessionization does not succeed.
function sessionize(cookie: string, keys: set[string]) : string
    {
    local id = "";
    local fields = split(cookie, /; /);

    local matches: table[string] of string;
    for ( i in fields )
        {
        local s = split1(fields[i], /=/);
        if (s[1] in keys)
            matches[s[1]] = s[2];
        }

    if ( |matches| == |keys| )
        for ( key in keys )
        {
            if (id != "")
                id += "; ";
            id += key + "=" + matches[key];
        }

    return id;
    }


# Track the cookie value inside HTTP.
event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( is_orig && name == "COOKIE" )
        c$http$cookie = value;
    }

# We use this event as an indicator that all headers have been seen. That is,
# this event guarantees that the HTTP state inside the connection record
# has all fields populated.
event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
    if ( ! is_orig || ! c$http?$cookie || c$http$cookie == "" )
        return;

    # Focus on Twitter requests only.
    if ( /twitter.com/ !in c$http$host )
        return;
    else 
	# print fmt("cookie: host %s", c$http$host);
	# print fmt("cookie: user-agent %s", c$http$user_agent);
	# print fmt("cookie: address %s : %s", c$id$orig_h, c$id$orig_p);
	

    # Create the relevant cookie subset that makes up the user session.
    local session_cookie = sessionize(c$http$cookie, twitter_cookie_keys);
		

    local format: string = "%F, %H:%M:%S";
    # Start tracking the current session cookie if we don't do so already.
    if ( session_cookie !in cookies )
	{
	cookies[session_cookie] =
	[
	    	$ip=c$id$orig_h,
	    	$user_agent=c$http$user_agent,
		$timestamp=c$http$ts,
		$timestamp_readable=strftime(format, c$http$ts)
	];
	return;
	}
	
    # check if the current user agent and ip address match the corresponedet values of the saved cookie
    if ( c$http$user_agent != cookies[session_cookie]$user_agent || c$id$orig_h != cookies[session_cookie]$ip)
	{
	    print fmt("Time         -Legitimate User: %s", cookies[session_cookie]$timestamp_readable);
	    print fmt("             -Eve:             %s", strftime(format, c$http$ts));

	    print fmt("User Agent   -Legitimate User: %s", cookies[session_cookie]$user_agent);
	    print fmt("             -Eve:             %s", c$http$user_agent);

	    print fmt("IP           -Legitimate User: %s", cookies[session_cookie]$ip);
	    print fmt("             -Eve:             %s", c$id$orig_h);	
	    print fmt("");
	    
	    #According to the Task only IP and browser information for Eve
	    #print fmt("Eve IP: %s", c$id$orig_h);
            #print fmt("Eve Browser information: %s", c$http$user_agent);
	}
 
    }