#!/usr/bin/env python
# MonkeyFist - The Dynamic Request Forgery Attack Tool
#
# MonkeyFist - Written by Nathan Hamiel
# nathan {at} neohaxor {dot} org
# Hexagon Security, LLC - Hexsec Labs
# www.hexsec.com
# 
#    Copyright (C) 2010  Nathan Hamiel, Hexagon Security
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    See <http://www.gnu.org/licenses/> for details.

import sys
import FistLib
from optparse import OptionParser

def main():
    usage = "usage: MonekyFist [options] [arguments] \n Run: MonkeyFist -h for help"
    parser = OptionParser(usage)
    parser.add_option("-a", "--about", dest="about",
                      action="store_true", help="Display program and version information")
    parser.add_option("-p", "--port", dest="port",
                      type="int", help="Port to run service on")
    parser.add_option("-r", "--random", dest="random",
                      action="store_true", help="Randomly cycle through payloads")
    parser.add_option("-s", "--standard", dest="standard",
                      action="store_true", help="Standard dynamic attack mode")
    parser.add_option("-t", "--test", dest="test",
                      action="store_true", help="Test mode. Does not perform attacks just logs")
    parser.add_option("-u", "--update", dest="update",
                      action="store_true", help="Check to see if an update is available")
    
    (options, args) = parser.parse_args()
    
    if len(sys.argv) < 2:
        print(usage)
        sys.exit(1)
    
    if options.about:
        FistLib.print_about()
        sys.exit(0)
        
    if options.port > 65535:
        print("You didn't specify a proper port number")
        sys.exit(1)
    else:
        port = options.port
        
    #########################
    # ToDo: There should be logic in here to determine if people are trying to
    # use more than one mode of operation at once.
    ########################
        
    if options.standard:
        
        # port = options.port
        type = "standard"
        FistLib.start_server(type, port)
        
    elif options.random:
        
        type = "random"
        FistLib.start_server(type, port)
    
    elif options.test:
        
        type = "test"
        FistLib.start_server(type, port)
        
    elif options.update:
        
        FistLib.check_update()
    
if __name__ == "__main__":
    main()