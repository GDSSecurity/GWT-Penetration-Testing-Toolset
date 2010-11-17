# -*- coding: utf-8 -*-
#!/usr/bin/env python

"""

    GwtParse v0.2
    Copyright (C) 2010 Ron Gutierrez

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""

import os
from optparse import OptionParser
from GWTParser import GWTParser

desc = "A tool for parsing GWT RPC Requests"

if __name__ == "__main__":
    parser = OptionParser(usage='usage: %prog [options]', description=desc, version='%prog 0.10')
    
    parser.add_option('-p', '--pretty', help="Output the GWT RPC Request in a human readible format", action="store_true")
    parser.add_option('-s', '--surround', help="String used to surround all fuzzable values", action="store", dest="surround_value")
    parser.add_option('-r', '--replace', help="String used to replace all fuzzable values", action="store", dest="replace_value")
    parser.add_option('-b', '--burp', help="Generates Burp Intruder Output", default=False, action="store_true")
    parser.add_option('-i', '--input', help="RPC Request Payload (Required)", action="store", dest="rpc_request")
    parser.add_option('-w', '--write', help="Writes Fuzz String to a new output file", action="store" )
    parser.add_option('-a', '--append', help="Appends Fuzz String to an existing output file", action="store" )
    
    (options, args) = parser.parse_args()

    if options.rpc_request:
    
        if options.surround_value and options.replace_value and options.burp:
            print( "\nCannot choose more then one output format.\n" )
            parser.print_help()
            exit()
        
        if options.surround_value and options.replace_value:
            print( "\nCannot choose more then one output format.\n" )
            parser.print_help()
            exit()
            
        if options.surround_value and options.burp:
            print( "\nCannot choose more then one output format.\n" )
            parser.print_help()
            exit()
            
        if options.replace_value and options.burp:
            print( "\nCannot choose more then one output format.\n" )
            parser.print_help()
            exit()
            
        gwt = GWTParser()
        
        if options.surround_value:
            gwt.surround_value = options.surround_value
        elif options.replace_value:
            gwt.replace_value = options.replace_value
        elif options.burp:
            gwt.burp = options.burp
        
        
        if options.write:
            if os.path.exists(options.write):
                print( "Output file entered already exists" )
                exit()
                
            fout = open( options.write, "w" )
            gwt.fout = fout
            
        elif options.append:
            fout = open( options.append, "a" )
            gwt.fout = fout
        
        gwt.deserialize( options.rpc_request )
        
        if options.pretty:
            gwt.display()
        
        gwt.get_fuzzstr()
        
        if gwt.fout:
            gwt.fout.close()
        
    else:
        print( "\nMissing RPC Request Payload\n" )
        parser.print_help()
        
    
    
