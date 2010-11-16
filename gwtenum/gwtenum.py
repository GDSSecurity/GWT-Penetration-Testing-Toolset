#!/usr/bin/env python

# GWTEnum v0.2
# Ron Gutierrez - Gotham Digital Science

import urllib2
import re
import pprint
import base64
import getpass
from optparse import OptionParser

desc = "A tool for enumerating GWT RPC methods"
methods = []
proxy_url = ""
basic_auth_encoded = ""
        
def get_global_val( varname, html_file ):
    for html_line in html_file:
        match = re.match( ".*," + re.escape(varname) +
            "\=\'([A-Za-z0-9_\.\!\@\#\$\%\^\&\*\(\)" 
            "\-\+\=\:\;\"\|\\\\/\?\>\,\<\~\`]+)\',", html_line )
        if not match is None:
            return match.group(1)


if __name__ == "__main__":
    parser = OptionParser( usage="usage: %prog [options]", 
        description=desc, 
        version='%prog 0.10' )
    
    parser.add_option('-p', '--proxy', 
        help="Proxy Host and Port (ie. -p \"http://proxy.internet.net:8080\")", 
        action="store" )
        
    parser.add_option('-b', '--basicauth', 
        help="User Basic Authentication ( Will be prompted for creds )", 
        action="store_true" )
        
    parser.add_option('-k', '--cookies', 
        help="Cookies to use when requesting the GWT Javascript Files (ie. -c \"JSESSIONID=AAAAAA\")", 
        action="store")
        
    parser.add_option('-u', '--url', 
        help="Required: GWT Application Entrypoint Javascript File (ie. *.nocache.js )", 
        action="store")
    
    (options, args) = parser.parse_args()
        
    if options.url is None:
        print( "\nMissing URL\n" )
        parser.print_help()
        exit()
            
    url = options.url
    gwt_docroot = '/'.join(url.split('/')[:-1])+'/'	
            
    req = urllib2.Request(url)
    
    handlers = [ urllib2.HTTPHandler() ]
    
    if url.startswith( "https://" ):
        try:
            import ssl
        except ImportError:
            print "SSL support not installed - exiting"
            exit()
            
        handlers.append( urllib2.HTTPSHandler() )
    
    if options.proxy:
        handlers.append( urllib2.ProxyHandler( {'http':'http://'+options.proxy}) )
        
    opener = urllib2.build_opener(*handlers)
    urllib2.install_opener( opener )
    
    if options.basicauth:
        username = raw_input( "Basic Auth Username: " )
        password = getpass.getpass( "Basic Auth Password: " )
        basic_auth_encoded = base64.encodestring( '%s:%s' % (username, password) ).strip()
        req.add_header( "Authorization", "Basic %s" % basic_auth_encoded )
    
    if options.cookies:
        req.add_header( "Cookie", options.cookies )
        
    response = urllib2.urlopen(req)
    the_page = response.read()
    
    html_files = re.findall( "([A-Z0-9]{30,35})", the_page )
    if html_files is None:
        print( "\nNo Cached HTML Files found\n" )
        exit()
        
    all_rpc_files = []
    how_many_html_files_to_read = 1
    
    for html_file in html_files:
        if how_many_html_files_to_read == 0:
           break
        how_many_html_files_to_read -= 1

        async_error_mess = ""
        invoke_method = ""
        cache_html = "%s%s.cache.html" % (gwt_docroot, html_file )
        print( "Analyzing %s" % cache_html )
        
        req = urllib2.Request( cache_html )
        
        if options.cookies:
            req.add_header( "Cookie", options.cookies )
            
        if options.basicauth:
            req.add_header( "Authorization", "Basic %s" % basic_auth_encoded )
                
        try:       
            response = urllib2.urlopen(req)     
        except urllib2.HTTPError:
            print( "404: Failed to Retrieve %s" % cache_html )
            continue
            
        the_page = response.readlines()
 
        for line in the_page:
        
            # Service and Method name Enumeration
            rpc_method_match = re.match( "^function \w+\(.*method\:([A-Za-z0-9_\$]+),.*$", line )
            
            if rpc_method_match:
                if rpc_method_match.group(1) == "a":
                    continue
                  
                rpc_js_function = rpc_method_match.group(0).split(';')
                service_and_method = ""
                
                method_name = get_global_val( rpc_method_match.group(1), the_page )
                if method_name is None:
                    continue
                    
                methods.append(  "%s( " % method_name.replace( '_Proxy.', '.' ) )
                
                # Parameter Enumeration
                for i in range(0, len(rpc_js_function)):
                    try_match = re.match( "^try{.*$", rpc_js_function[i] )
                    if try_match:
                        i += 1
                        func_match = re.match( "^([A-Za-z0-9_\$]+)\(.*", rpc_js_function[i] )
                        payload_function = ""
                        if func_match:
                            payload_function = func_match.group(1)
                        
                        i += 1
                        param_match = re.match( "^"+re.escape(payload_function)+
                            "\([A-Za-z0-9_\$]+\.[A-Za-z0-9_\$]+,([A-Za-z0-9_\$]+)\)", 
                            rpc_js_function[i] )
                            
                        num_of_params = 0
                        if param_match:
                            num_of_params = int(get_global_val( param_match.group(1), the_page ))
                        
                        for j in range( 0, num_of_params ):
                            i += 1
                            
                            param_var_match = re.match( "^"+re.escape(payload_function)+
                                "\([A-Za-z0-9_\$]+\.[A-Za-z0-9_\$]+,[A-Za-z0-9_\$]+\+"
                                "[A-Za-z0-9_\$]+\([A-Za-z0-9_\$]+,([A-Za-z0-9_\$]+)\)\)$", 
                                rpc_js_function[i] )
                                
                            if param_var_match:
                                param = get_global_val( param_var_match.group(1), the_page )
                                methods[-1] = methods[-1]+param+","
                             
                        a_method = methods[-1][:-1]
                        methods[-1] = a_method + " )"
                        break
    
    line_decor = "\n===========================\n"
    print( "\n%sEnumerated Methods%s" % ( line_decor, line_decor ) )
    methods = sorted(list(set(methods))) #uniq
        
    for method in methods:
        print( method )
    
    print( "\n\n" )
