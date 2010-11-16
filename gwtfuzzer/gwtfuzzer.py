# -*- coding: utf-8 -*-
#!/usr/bin/env python

"""
    GwtFuzzer v0.2
    Ron Gutierrez <rgutierrez@gdssecurity.com>
    Gotham Digital Science
"""

import urllib2
import urllib
import os
import os.path
import time
from GWTParser import GWTParser
from gds.pub.burp import parse
from itertools import product
from optparse import OptionParser

'''
    Globals
'''

attacklog = []
param_manip_log = []


def replay( burpobj, fuzzified, attackstr, gwtparsed, log ):
    global options
    
    headers = burpobj.get_request_headers()

    if options.cookies is not None:   
        headers["Cookie"] = options.cookies
        
    headers["Content-Length"] = str(len(fuzzified))
    
    req = urllib2.Request(burpobj.url.geturl(), fuzzified, headers )
    
    handlers = [ urllib2.HTTPHandler() ]

    if options.proxy is not None:    
        handlers.append( urllib2.ProxyHandler( {'http':options.proxy} ) )
        
    opener = urllib2.build_opener(*handlers)
    urllib2.install_opener( opener )

    errors_found = []    
    try:    
        resp = urllib2.urlopen(req)
        data = resp.read()
        
        # Check for error messages
        errors_found = check_errors(data)

        # Check to see if a exception message was returned        
        if is_exception(data):
            errors_found.append( "GWT Exception Returned" )
        
        # Success        
        log.append( { 'method':gwtparsed.rpc_deserialized[2]+"."+gwtparsed.rpc_deserialized[3],
            'request_url':burpobj.url.geturl(),
                            'request_headers':headers,
                           'request_payload':fuzzified,
                           'attack': attackstr,
                           'response_status':200,
                           'response_content':data,
                           'response_size':len(data),
                           'errors_found':errors_found })
        
    except urllib2.HTTPError, e:
        # Request did not return a 200 OK
        log.append( {'method':gwtparsed.rpc_deserialized[2]+"."+gwtparsed.rpc_deserialized[3],
            'request_url':burpobj.url.geturl(),
                           'request_headers':headers,
                           'request_payload':fuzzified,
                           'attack': attackstr,
                           'response_status':e.code,
                           'response_content':e.read(),
                           'response_size':len(e.read()),
                           'errors_found':errors_found })
    except urllib2.URLError, e:
        # Host could not be reached
        log.append( {'method':gwtparsed.rpc_deserialized[2]+"."+gwtparsed.rpc_deserialized[3],
            'request_url':burpobj.url.geturl(),
                           'request_headers':headers,
                           'request_payload':fuzzified,
                           'attack': attackstr,
                           'response_status':'Python URLError Exception',
                           'response_content':e.reason(),
                           'response_size':0,
                           'errors_found':errors_found})
        
        print( "Request failed: "+burpobj.url.geturl()+"("+e.reason+")" )


def check_errors( data ):
    global errors
    found = []

    for error in errors:
        if data.find( error ) != -1:
            found.append( error )
            print( "found "+error )

    return found


def is_exception( data ):
    if data.find( "//EX[", 0, 8 ) != -1:
        return True

    return False


def escape( str ):
    return str.replace( '<', '&lt;' ).replace( '>', '&gt;' ).replace( '"', '&quot' ).replace( '\'', '&#39;')


def filter_gwt_reqs( parsed ):
    filtered = []
    for burpobj in parsed:
        headers = burpobj.get_request_headers()
        if "Content-Type" in headers:
            if headers["Content-Type"].find("text/x-gwt-rpc") != -1:
                filtered.append( burpobj )
            
    return filtered    


def get_number_range( num ):
    if num < options.idrange:
        return 0, num+options.idrange

    begin = int(num)-int(options.idrange)
    end = int(num)+int(options.idrange) 
    return begin, end 


def load_strings( list, filename ):
    if os.path.exists( filename ):
        f = open( filename, 'r' )

        for line in f:
            if line.find( "# ", 0, 2 ) == -1: # Ignore FuzzDB comments
                list.append( line.strip() )
               
        f.close()
    else:
        print( "Error: "+filename+" does not exist" )
        exit()

      
def fuzz( burpobj ):
    global options, attacks, attacklog, param_manip_log

    # Parse the gwt string
    gwtparsed = GWTParser()
    gwtparsed.deserialize( burpobj.get_request_body() )
    
    gwtlist = burpobj.get_request_body().split('|')

    # This is where the magic happens.. Special Thanks to Marcin W.

    # Test all GWT requests using the attack strings submitted
    for( idx, param ), fuzzy in product( enumerate(gwtlist), attacks ):
        # Check to see if index was marked as a fuzzible string value by GWTParse
        if idx in gwtparsed.fuzzmarked and gwtparsed.fuzzmarked[idx] == "%s":
            fuzzified = "%s|%s|%s" %('|'.join(gwtlist[:idx]), fuzzy.replace('|','\!'), '|'.join(gwtlist[idx+1:]))
            replay( burpobj, fuzzified, fuzzy, gwtparsed, attacklog ) # Submit the request

    # Test all GWT request for Parameter Manipulation
    for idx, param in enumerate( gwtlist ):
        if idx in gwtparsed.fuzzmarked and gwtparsed.fuzzmarked[idx] == "%d":
            begin, end = get_number_range( param )
            for i in range( int(begin), int(end) ):
                fuzzified = "%s|%s|%s" %('|'.join(gwtlist[:idx]), str(i), '|'.join(gwtlist[idx+1:]))
                replay( burpobj, fuzzified, str(i), gwtparsed, param_manip_log ) #Submit the request
            

def reportfuzz( logdir ):
    global attacklog
        
    f = open( logdir+"//gwtfuzz.html", 'w' )

    f.write( '''
    <html>
    <head>
        <title>GWTFuzz Results</title>
        <style type="text/css">
            td, th{
                font-family: sans-serif;
                font-size: 12px;
                border: thin solid black;
                word-wrap: break-word;
                border-spacing: 0;
                padding: 1px 1px 1px 1px;
            }

            tr.error{
                background-color: #FFCC66;
            }
        </style>        
    </head>
    <body>
    <h2>Fuzz Results</h2>
    <table cellspacing=0 style="border: thin solid black;">
    <tr>
        <td>ID</th>
        <th>Endpoint URL</th>
        <th>RPC Method</th>
        <th>Attack</th>
        <th>Request Data</th>
        <th>Resp Status</th>
        <th>Resp Size</th>
        <th>Resp Content</th>
        <th>Errors Found</th>
    </tr>''' )
    
    for idx, entry in enumerate(attacklog):
        if len(entry['errors_found']) > 0:
            f.write( '<tr class="error">' )
        elif entry['response_status'] != 200:
            f.write( '<tr class="error">' )
        else:
            f.write( '<tr>' )
            
        f.write( '<td style="max-width:300px;text-align:right">'+str(idx)+'</td>' +
                 '<td style="max-width:300px;">'+escape(entry['request_url'])+'</td>' +
                 '<td style="max-wdth:300px;">'+escape(entry['method'])+'</td>' +
                 '<td style="max-width:300px;text-align:center">'+escape(entry['attack'])+'</td>' +
               '<td style="max-width:450px;">'+escape(entry['request_payload'])+'</td>' +
               '<td style="width=10px;max-width:10px;text-align:right">'+str(entry['response_status'])+'</td>' +
               '<td style="width=10px;max-width:10px;text-align:right">'+str(entry['response_size'])+'</td>' +
               '<td style="max-width:150px;"><a href="responses/'+str(idx)+'.txt" target="_new">View Response</a></td>' +
                '<td style="max-width:100px;">' )

        errorstr = ""
        
        for error in entry['errors_found']:
            errorstr = errorstr + escape(error) + ", "

        errorstr = errorstr[:-2]

        f.write( errorstr+'</td></tr>' )

        # Write the HTTP response into a text file
        f2 = open( logdir+'//responses/'+str(idx)+'.txt', 'w' ) 
        f2.write( entry['response_content'] )
        f2.close()
    
    f.write( '</table></body></html>' )
    f.close()

    print( "Results saved to "+logdir )    

def reportparam( logdir ):
    global param_manip_log
    
    f = open( logdir+"//param_manip.html", 'w' )

    f.write( '''
    <html>
    <head>
        <title>GWT Parameter Manipulation Results</title>
        <style type="text/css">
            td, th{
                font-family: sans-serif;
                font-size: 12px;
                border: thin solid black;
                word-wrap: break-word;
                border-spacing: 0;
                padding: 1px 1px 1px 1px;
            }
            tr.status{
                background-color: #FFCC66;
            }

            tr.error{
                background-color: #FF3333;
            }
        </style>        
    </head>
    <body>
    <h2>GWT Parameter Manipulation Results</h2>
    <table cellspacing=0 style="border: thin solid black;">
    <tr>
        <td>ID</th>
        <th>Endpoint URL</th>
        <th>RPC Method</th>
        <th>Attack</th>
        <th>Request Data</th>
        <th>Resp Status</th>
        <th>Resp Size</th>
        <th>Resp Content</th>
    </tr>''' )
    
    for idx, entry in enumerate(param_manip_log):     
        f.write( '<tr><td style="max-width:300px;text-align:right">'+str(idx)+'</td>' +
                 '<td style="max-width:300px;">'+escape(entry['request_url'])+'</td>' +
                 '<td style="max-wdth:300px;">'+escape(entry['method'])+'</td>' +
                 '<td style="max-width:300px;text-align:center">'+escape(entry['attack'])+'</td>' +
               '<td style="max-width:450px;">'+escape(entry['request_payload'])+'</td>' +
               '<td style="width=10px;max-width:10px;text-align:right">'+str(entry['response_status'])+'</td>' +
               '<td style="width=10px;max-width:10px;text-align:right">'+str(entry['response_size'])+'</td>' +
               '<td style="max-width:150px;"><a href="responses/p'+str(idx)+'.txt" target="_new">View Response</a></td></tr>' +
                '<td style="max-width:100px;">' )
            
        # Write the HTTP response into a text file
        f2 = open( logdir+'//responses//p'+str(idx)+'.txt', 'w' ) 
        f2.write( entry['response_content'] )
        f2.close()
    
    f.write( '</table></body></html>' )
    f.close()    

      
if __name__ == "__main__":
    global options, attacks, errors
    attacks = []
    errors = []
    
    parser = OptionParser( usage="usage: %prog [options]",
                           description='Automates the fuzzing of GWT RPC requests',
                           version='%prog 0.10' )

    parser.add_option('-b', '--burp',
                      help='Burp logfile to fuzz',
                      action='store' )

    parser.add_option('-f', '--fuzzfile',
                      help='File containing attack strings',
                      action='store' )

    parser.add_option('-e', '--errorfile',
                      help='File containing error messages',
                      action='store' )

    parser.add_option('-o', '--output',
                      help='Directory to store results',
                      action='store' )

    parser.add_option('-k', '--cookies',
                      help='Cookies to use when requesting GWT RPC pages',
                      action='store' )

    parser.add_option('-p', '--proxy',
                      help='Proxy Host and Port (e.g. -p "http://proxy.internet.net:8080"',
                      action='store' )

    parser.add_option('-i', '--idrange',
                      help='Range of decrements and increments to test parameter manipulation with',
                      action='store' )

    (options, args) = parser.parse_args()

    if options.burp is None:
        print( "\nError: Missing Burp log file\n" )
        parser.print_help()
        exit()
    elif options.fuzzfile is None:
        print( "\nError: Missing fuzz file\n" )
        parser.print_help()
        exit()

    if options.idrange and options.idrange < 1:
        options.idrange = 100
        print( "Invalid ID Range Entered: ID Range has been set to 100\n" )
    elif options.idrange is None:
        options.idrange = 100
        print( "ID Range for Parameter Manipulation Testing has been set to 100\n" )
        
    parsed = None

    # Parse the Burp log using the GDS Burp API    
    if os.path.exists( options.burp ):
        print( "Parsing Burp logfile" )
        parsed = parse( options.burp )
    else:
        print( "\nBurp log file entered does not exist\n" )
        exit()

    logdir = ""
    
    if options.output and os.path.exists( options.output ):
        print( "Error: Output directory already exists." )
        exit()
    elif options.output:
        logdir = options.output
    else:
        logdir = "gwtfuzz_results"+time.strftime("%Y%m%d%H%M%S")

    os.mkdir( logdir )
    os.mkdir( logdir+"//responses" )

    if options.fuzzfile:
        load_strings(attacks, options.fuzzfile)

    if options.errorfile:
        load_strings(errors, options.errorfile)
        
    # Filter out the GWT RPC Requests from the log    
    filtered = filter_gwt_reqs(parsed)

    print( "Fuzzing has commenced" )    
    # Fuzz each GWT RPC Request
    for burpobj in filtered:
        fuzz( burpobj )

    # Generate Parameter Manipulation Report
    reportparam( logdir )
    
    reportfuzz( logdir )
    
