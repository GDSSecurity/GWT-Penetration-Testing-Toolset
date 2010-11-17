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

import sys
import re
import pprint
from Parameter import Parameter

reload(sys)
sys.setdefaultencoding('utf-8')


#################################################
#
#   Java Primitive Types and Object Wrappers
#
#################################################

FUZZ_STRING = "%s"
FUZZ_DIGIT = "%d"

STRING_OBJECT = "java.lang.String"
INTEGER_OBJECT = "java.lang.Integer"
DOUBLE_OBJECT = "java.lang.Double"
FLOAT_OBJECT = "java.lang.Float"
BYTE_OBJECT = "java.lang.Byte"
BOOLEAN_OBJECT = "java.lang.Boolean"
SHORT_OBJECT = "java.lang.Short"
CHAR_OBJECT = "java.lang.Char"
LONG_OBJECT = "java.lang.Long"

PRIMITIVES_WRAPPER = [ STRING_OBJECT, INTEGER_OBJECT, DOUBLE_OBJECT, FLOAT_OBJECT, BYTE_OBJECT, BOOLEAN_OBJECT, SHORT_OBJECT, CHAR_OBJECT ]

LONG = "J"
DOUBLE = "D"
FLOAT = "F"
INT = "I"
BYTE = "B"
SHORT = "S"
BOOLEAN = "Z"
CHAR = "C"

PRIMITIVES = [ "J", "D", "F", "I", "B", "S", "Z", "C" ] 
NUMERICS = [ INT, CHAR, BOOLEAN, BYTE, SHORT, INTEGER_OBJECT, CHAR_OBJECT, BYTE_OBJECT, BOOLEAN_OBJECT, SHORT_OBJECT ]

ARRAYLIST = "java.util.ArrayList"
LINKEDLIST = "java.util.LinkedList"
VECTOR = "java.util.Vector"

ListTypes = [ ARRAYLIST, LINKEDLIST, VECTOR ]

prev_index = 0
INDENTATION = 15

class GWTParser(object):
    
    def _cleanup(self):
        self.data = []
        self.rpc_deserialized = []
        self.rpc_list = []
        self.indices = []
        self.data_types = []
        self.parameters = []
        self.stream_version = 0
        self.flags = ""
        self.columns = 0
        self.parameter_idx = 0
        self.fuzzmarked = dict()
        
    '''
    Sets a value as fuzzable
    '''
    def _set_fuzzable( self, idx, fuzz_value ):
        fuzz_idx = int(idx)+2
        
        if self.surround_value:
            if not fuzz_idx in self.fuzzmarked:
                self.rpc_list_fuzzable[fuzz_idx] = self.surround_value+self.rpc_list_fuzzable[fuzz_idx]+self.surround_value
        
        elif self.replace_value:
            self.rpc_list_fuzzable[fuzz_idx] = self.replace_value
        
        elif self.burp:
            if not fuzz_idx in self.fuzzmarked:
                self.rpc_list_fuzzable[fuzz_idx] = '§'+self.rpc_list_fuzzable[fuzz_idx]+'§'
                
        else:
            self.rpc_list_fuzzable[fuzz_idx] = fuzz_value
        
        self.fuzzmarked[fuzz_idx] = fuzz_value
        
            
    '''
    Check if the next index value is an integer or a data index
    '''
    def _nextval_is_an_integer(self, curr_index):
        if len(self.indices) == 0:
            return False
        
        # If the index is out of data array scope
        if int(self.indices[0]) <= 4 or int(self.indices[0]) > self.columns:
            return True
            
        # If next index is the increment of the previous    
        if int(curr_index) == int(self.indices[0])-1:
            if len(self.indices) > 1:
                if int(self.indices[0]) == int(self.indices[1]):
                        return True
        
        return False
        

    '''
    Put back the index that was pop previously
    '''
    def _indice_rollback(self, prev_index):
        self.indices_read -= 1
        self.indices.insert(0,prev_index)
        
        
    ''' 
    Is the next value an object type name
    '''
    def _is_an_object(self, value):
        obj_check = re.compile( ".*/\d+" )
        match = obj_check.match(value)
        
        if match:
            return True

        return False

    ''' 
    Check to see if the type is an array of primitives
    '''
    def _is_a_primitive_array(self, data_type):
        arr_check = re.compile( "\[(\w)/\d+" )
        match = arr_check.match(data_type)
        
        if match and match.group(1) in PRIMITIVES:
            self.parameters[self.pidx].typename = match.group(1)
            self.parameters[self.pidx].is_array = True
            return True
            
        return False
    
    '''
    Is the passed in value the subtype value for the current parameters typename
    '''
    def _is_object_subtype( self, data_type ):
        typename = ""
        
        if self.parameters[self.pidx].is_list:
            typename = self.parameters[self.pidx].subtype
        else:
            typename = self.parameters[self.pidx].typename
    
        subtype_check = re.compile( typename+"/\d+" )
        match = subtype_check.match( data_type )

        if match:
            return True
        
        return False
    
    '''
    Check to see if the type is array of objects
    '''
    def _is_an_object_array( self, data_type):
        arr_check = re.compile( "\[L(.*);/\d+" )
        match = arr_check.match(data_type)

        if match:
            self.parameters[self.pidx].typename = match.group(1)
            self.parameters[self.pidx].is_array = True
            return True
            
        return False
        
    '''
    Check to see if data_type is a ListType
    '''
    def _is_list_type( self, data_type ):
        if self._get_typename(data_type) in ListTypes:
            return True
            
        return False
        
    
    '''
    Check to see if the index passed in is an integer value
        - This check needs some major work
    '''
    def _indice_is_intval( self, idx ):
        # If the index is out of data array scope
        if int(self.indices[int(idx)]) <= 4 or int(self.indices[int(idx)]) > self.columns:
            return True
        
        return False
                    
    
    '''
    Check to see if the remaining method parameters are all numeric
    '''
    def _remaining_params_are_numeric( self, tracker_idx):      
        for i in range( self.pidx+1, len(self.parameters)):
            if not self._get_typename(self.parameters[i].typename) in NUMERICS:
                return False
                
        return True
        
    
    '''
    Checks to see whether we should stop reading values into a custom object
    '''
    def _is_end_of_object( self, prev_index, value ):   
        tracker_idx = 0
        found = False
        
        if self._remaining_params_are_numeric( tracker_idx ):

            if len(self.indices) == len(self.parameters[self.pidx+1:]):
                prev_index = self.indices[0]
                self._add_stringval(value)
                return True
            else:
                return False
                
        if len(self.parameters[self.pidx+1:]) == len(self.indices):
            prev_index = self.indices[0]
            self._add_stringval(value)
            return True
            
        for i in range( self.pidx+1, len( self.parameters ) ):
                    
            # Look Into the Future and see if the parameter values are still there
            for j in range( tracker_idx, len(self.indices) ):
                
                if self._get_typename(self.parameters[i].typename) in NUMERICS: 
                    
                    if self._indice_is_intval(j):
                        found = True
                        tracker_idx = j
                        continue
                    
                elif self._get_typename(self.parameters[i].typename) == STRING_OBJECT:
                    
                    # If the index is out of data array scope
                    if int(self.indices[j]) <= 4 or int(self.indices[j]) > self.columns:
                        continue
                                            
                    if self._is_an_object( self.data[int(self.indices[j])] ) is False:
                        found = True
                        tracker_idx = j
                        break
                    
                else:
                    # If the index is out of data array scope
                    if int(self.indices[j]) <= 4 or int(self.indices[j]) > self.columns:
                        continue
                        
                    # This must be a custom object. Check for the subtype..
                    if self._get_typename(self.data[int(self.indices[j])]) == self._get_typename(self.parameters[i].typename):
                        found = True
                        tracker_idx = j
                        break
                        
            if not found:
                return True # Did not find the next parameter so the current value is the next method param
            else:
                found = False 
                
        return False
            
    '''
    Removes the "/" and digits from a typename
    '''
    def _get_typename( self, data_type):
        subtype_check = re.compile( "(.*)/\d+" )
        match = subtype_check.match(data_type)
        
        if match:
            return match.group(1)
        
        return data_type
    
    
    '''
    Get the next index or integer value
    '''
    def _pop_index(self):
        try:
            self.indices_read += 1
            index = int(self.indices.pop(0))
        except TypeError:
            print ("Invalid Integer given for indices")
            sys.exit()
    
        return index
    
    
    '''
    Get the next float value
    '''
    def _pop_float_index(self):
        try:
            self.indices_read += 1
            index = float(self.indices.pop(0))
        except TypeError:
            print ("Invalid float value read")
            sys.exit()
    
        return index
    
    
    '''
    Pop the next index value and then return the corresponding value
    from the data table
    '''
    def _get_nextval(self):
        return self.data[self._pop_index()]
    
    
    def _add_intval(self):
        if self.parameters[self.pidx].flag:
            self.parameters[self.pidx].values[self.aidx].values.append(self._pop_index())
        elif self.parameters[self.pidx].is_list and self.parameters[self.pidx].is_custom_obj:
            self.parameters[self.pidx].values[self.lidx].values.append(self._pop_index())
        else:
            self.parameters[self.pidx].values.append(self._pop_index())
    
    
    def _add_stringval(self, value):
        if self.parameters[self.pidx].flag:
            self.parameters[self.pidx].values[self.aidx].values.append(value)
        elif self.parameters[self.pidx].is_list and self.parameters[self.pidx].is_custom_obj:
            self.parameters[self.pidx].values[self.lidx].values.append(value)
        else:
            self.parameters[self.pidx].values.append(value)
        
        
    ###################################
    #
    # Parsing Methods
    #
    ####################################
    
    def _parse_read_string(self):
        self._set_fuzzable( self.indices[0], FUZZ_STRING )
        
        if self.parameters[self.pidx].flag:
            self.parameters[self.pidx].values[self.aidx].append(self._get_nextval())
        else:
            if self.parameters[self.pidx].is_list:
                subtype = self._get_nextval()
                
            self.parameters[self.pidx].values.append(self._get_nextval())
    
    
    def _parse_read_int_byte_short_char(self, is_wrapper=False):
        if is_wrapper:
            subtype = self._get_nextval()
        
        self._set_fuzzable( self.indices_read+self.columns, FUZZ_DIGIT )
        
        if self.parameters[self.pidx].flag:
            self.parameters[self.pidx].values[self.aidx].values.append(self._pop_index())
        else:
            self.parameters[self.pidx].values.append(self._pop_index())
        
        
    def _parse_read_long(self, is_wrapper=False):
        if is_wrapper:
            subtype = self._get_nextval()
            
        value1 = self._pop_float_index()
        value2 = self._pop_float_index()
        
        self._set_fuzzable( self.indices_read+self.columns-2, FUZZ_DIGIT )
        self._set_fuzzable( self.indices_read+self.columns-1, FUZZ_DIGIT )
        
        
        if value2 > 0:  
            self.parameters[self.pidx].values.append( str(value1) + str(value2) )
        else:
            self.parameters[self.pidx].values.append( str(value1) )
    
    
    def _parse_read_double_float(self, is_wrapper=False):
        if is_wrapper:
            subtype = self._get_nextval()
            
        self._set_fuzzable( self.indices_read+self.columns, FUZZ_DIGIT )
        self.parameters[self.pidx].values.append(self._pop_float_index())
    
    def _parse_primitive_array(self):
        subtype = self._get_nextval()
        how_many = self._pop_index()
        
        for i in range(how_many):
            self._parse_value( self.parameters[self.pidx].typename )
        
    def _parse_object_array(self):
        if self.parameters[self.pidx].flag is False:
            subtype = self._get_nextval()
            
        how_many = self._pop_index()
        
        self.aidx = 0 
        for i in range(how_many):
            self._parse_value(self.parameters[self.pidx].typename )
            self.aidx += 1
        
    def _parse_read_boolean(self):      
        self._set_fuzzable( self.indices_read+self.columns, FUZZ_DIGIT )
        int_value = self._pop_index()
            
        if int_value == 1:
            self.parameters[self.pidx].values.append( "true" )
        else:
            self.parameters[self.pidx].values.append( "false" )
                
    def _parse_read_list(self, list_type, set_list_flag=True):
        if self.parameters[self.pidx].flag is False:
            
            if set_list_flag:
                self.parameters[self.pidx].is_list = True
                
            self.parameters[self.pidx].typename = list_type
            subtype = self._get_nextval()
            
        else:
            self.parameters[self.pidx].values[self.aidx].typename = list_type
            
        how_many = self._pop_index()
        self.lidx = 0
        
        for i in range(how_many):
        
            prev_index = self.indices[0]
            
            if self.parameters[self.pidx].flag: # Reading a List within a Custom Object
                subtype = self._get_typename(self._get_nextval())
                self.parameters[self.pidx].values[self.aidx].subtype = subtype
                self._indice_rollback(prev_index)
                self._parse_value(subtype)
                
            else: # Read values within a List Method Parameter
                self.parameters[self.pidx].subtype = self._get_typename(self._get_nextval())
                self._indice_rollback(prev_index)
                self._parse_value(self.parameters[self.pidx].subtype)
    
            self.lidx += 1
    
    
    def _parse_read_object(self,name):
        
        if len( self.indices ) > 0:
            prev_index = self.indices[0]
        
        self.parameters[self.pidx].is_custom_obj = True
        value = self._get_nextval()
        
        if self.parameters[self.pidx].is_array and self.parameters[self.pidx].is_custom_obj:
            customParam = Parameter( value )
            customParam.is_custom_obj = True
            self.parameters[self.pidx].values.append( customParam )
            self.parameters[self.pidx].flag = True
        
        if self.parameters[self.pidx].is_list and self.parameters[self.pidx].is_custom_obj:
            customParam = Parameter(value)
            customParam.is_custom_obj = True
            self.parameters[self.pidx].values.append(customParam)
        
        # If this is the final parameter just read the remaining data as member variables
        if len(self.parameters)-1 == self.pidx:

            while len(self.indices) > 0: # Read till the end of the index table
                
                if self._nextval_is_an_integer( prev_index ):

                    prev_index = self.indices[0]
                    self._set_fuzzable( self.indices_read+self.columns, FUZZ_DIGIT )
                    self._add_intval()
                    continue
                    
                else:
                    prev_index = self.indices[0]
                    value = self._get_nextval()
                    
                if self.parameters[self.pidx].is_array or self.parameters[self.pidx].is_list: # Am I reading an array of objects?   
                
                    if self._is_object_subtype(value): # Did I just read in an object subtype?
                        self._indice_rollback(prev_index)
                        break # Stop reading object and move onto the next object in the array
                    
                if self._is_list_type( value ):
                
                    if self.parameters[self.pidx].flag is False:
                        self._indice_rollback(prev_index)
                        
                    self._parse_read_list(self._get_typename(value), False)
                    
                elif self._is_an_object(value): # Is the value I just read in a subtype for another class
                    prev_index = self.indices[0]

                else:
                    self._add_stringval(value)
                    self._set_fuzzable( prev_index, FUZZ_STRING )
                    
        else: # There are more parameters so we must be careful with the parsing

            while len(self.indices) > 0: 
            
                if self._nextval_is_an_integer( prev_index ):
                    self._set_fuzzable( self.indices_read+self.columns, FUZZ_DIGIT )
                    prev_index = self.indices[0]
                    self._add_intval()
                else:
                    prev_index = self.indices[0]
                    value = self._get_nextval()
                            
                    if self.parameters[self.pidx].is_array or self.parameters[self.pidx].is_list:
                    
                        if self._is_object_subtype(value):
                            self._indice_rollback(prev_index)
                            break;
                
                    if self._is_end_of_object( prev_index, value ):

                        if self.parameters[self.pidx].is_list or self.parameters[self.pidx].is_array:
                            self.pidx += 1
                            self._indice_rollback(prev_index)
                            self._parse_value( self.parameters[self.pidx].typename )
                            
                        else:
                            if not self._get_typename(self.parameters[self.pidx+1].typename) in NUMERICS:
                                self._indice_rollback(prev_index)
                            break
                            
                    elif self._is_an_object( value ):
                        continue
                        
                    else: # store value
                        self._set_fuzzable( prev_index, FUZZ_STRING )
                        prev_index = self.indices[0]
                        self._add_stringval(value)                      
            
        self.parameters[self.pidx].flag = False
                            
    '''
    Split the object into a list and remove the last element
    The RPC String ends with a '|' so this will create an empty element
    '''
    def _read_string_into_list(self):
        # This copy is used to keep track of fuzzable values
        self.rpc_list_fuzzable = list(self.rpc_string.split('|'))
        self.rpc_list_fuzzable.pop()
        
        # This copy is used to parsing and will have values removed during parsing
        self.rpc_list = self.rpc_string.split('|')
        self.rpc_list.pop()
    
    
    '''
    Store and remove the first three elements of the list
    '''
    def _get_headers(self):
        try:
            self.stream_version = int(self.rpc_list.pop(0))
            self.flags = self.rpc_list.pop(0)
            self.columns = int(self.rpc_list.pop(0))
        except TypeError:
            print ("Invalid Integer given for the stream_version or number of columns")
            sys.exit()
    
    
    '''
    Store the data inside of the serialized object
    I add in an empty string in the 0 Element in order to
    stay uniform with the indices table in the RPC Object
    '''
    def _get_data(self):
        self.data = self.rpc_list[0:self.columns]
        self.data.insert(0,"")
    
    
    '''
    Store the indices that are found at the end of the RPC serialized object
    '''
    def _get_indices(self):
        self.indices = self.rpc_list[self.columns:]
    
    
    '''
    Parses a value from the string table
    '''
    def _parse_value(self, data_type):
        
        if self._get_typename(data_type) == STRING_OBJECT:
            self._parse_read_string()
                    
        elif self._get_typename(data_type) == INT or data_type == BYTE or data_type == SHORT or data_type == CHAR:
            self._parse_read_int_byte_short_char()
            
        elif self._get_typename(data_type) == INTEGER_OBJECT or data_type == BYTE_OBJECT or data_type == SHORT_OBJECT or data_type == CHAR_OBJECT:
            self._parse_read_int_byte_short_char(True)
            
        elif self._get_typename(data_type) == LONG:
            self._parse_read_long()
            
        elif self._get_typename(data_type) == LONG_OBJECT:
            self._parse_read_long(True)
            
        elif self._get_typename(data_type) == DOUBLE or data_type == FLOAT:
            self._parse_read_double_float()
        
        elif self._get_typename(data_type) == DOUBLE_OBJECT or data_type == FLOAT_OBJECT:
            self._parse_read_double_float(True)
            
        elif self._is_a_primitive_array(data_type):
            self._parse_primitive_array()
            
        elif self._is_an_object_array(data_type):
            self._parse_object_array()

        elif self._get_typename(data_type) == BOOLEAN:
            self._parse_read_boolean()
        
        elif self._is_list_type(data_type):
            self._parse_read_list(data_type)
            
        else:
            self._parse_read_object(data_type)
            
    '''
    Parses the GWT-RPC Request Payload
    '''
    def _parse(self):
        self.rpc_deserialized = []
        self.parameters = [] # Stores Parameter names and values read in from the request
        self.pidx = 0 # Index value used to know which Parameter we are currently writing into
        self.indices_read = 1 # Keeps track how many indices we have read
        
        '''
        Store the first four values
        Hostname, Hash, Class Name, Method
        '''
        for i in range(4):
            self.rpc_deserialized.append(self._get_nextval())
        
        for index in self.indices:
            num_of_params = self._pop_index() # Number of Method parameters
            
            for i in range(num_of_params):
                self.parameters.append( Parameter(self._get_nextval()) )
                
            for param in self.parameters:
                if num_of_params > self.pidx: # If parameter index is greater than number of params then we are done
                    self._parse_value(param.typename)
                    self.pidx += 1
    
    
    '''
    Handles the parsing of the RPC string
    '''
    def deserialize(self, rpc_string):
        self._cleanup()
        self.rpc_string = rpc_string
        self._read_string_into_list()
        self._get_headers()
        self._get_data()
        self._get_indices()
        try:
            self._parse()
        except IndexError:
            print( "Encountered Error During Parsing" )
    
    def get_fuzzstr(self):
        fuzzstr = "|".join( self.rpc_list_fuzzable )+"|"
        
        if self.fout:   
            self.fout.write( fuzzstr+"\n" )
            
        else:
            print( "\nGWT RPC Payload Fuzz String\n" )
            print( fuzzstr+"\n" )
        
    '''
    Prints out the deserialized method call in a user friendly format
    '''
    def display(self):
    
        if self.fout:
            self.fout.write("==================================\n")
            self.fout.write(str("Serialized Object:").rjust(INDENTATION) + "\n" + self.rpc_string + "\n\n")
            self.fout.write(str("Stream Version:").rjust(INDENTATION) + "\t" + str(self.stream_version)+"\n")
            self.fout.write(str("Flags:").rjust(INDENTATION) + "\t" + self.flags+"\n")
            self.fout.write(str("Column Numbers:").rjust(INDENTATION) + "\t" + str(self.columns)+"\n")
            self.fout.write(str("Host:").rjust(INDENTATION) + "\t" + self.rpc_deserialized[0]+"\n")
            self.fout.write(str("Hash:").rjust(INDENTATION) + "\t" + self.rpc_deserialized[1]+"\n")
            self.fout.write(str("Class Name:").rjust(INDENTATION) + "\t" + self.rpc_deserialized[2]+"\n")
            self.fout.write(str("Method:").rjust(INDENTATION) + "\t" + self.rpc_deserialized[3] + "\n")
            self.fout.write(str("# of Params:").rjust(INDENTATION) + "\t" + str(len(self.parameters)) + "\n")
            self.fout.write(str("Parameters:").rjust(INDENTATION)+"\n")
        else:   
            print (str("\nSerialized Object:").rjust(INDENTATION) + "\n" + self.rpc_string + "\n")
            print (str("Stream Version:").rjust(INDENTATION) + "\t" + str(self.stream_version))
            print (str("Flags:").rjust(INDENTATION) + "\t" + self.flags)
            print (str("Column Numbers:").rjust(INDENTATION) + "\t" + str(self.columns))
            print (str("Host:").rjust(INDENTATION) + "\t" + self.rpc_deserialized[0])
            print (str("Hash:").rjust(INDENTATION) + "\t" + self.rpc_deserialized[1])
            print (str("Class Name:").rjust(INDENTATION) + "\t" + self.rpc_deserialized[2])
            print (str("Method:").rjust(INDENTATION) + "\t" + self.rpc_deserialized[3])
            print (str("# of Params:").rjust(INDENTATION) + "\t" + str(len(self.parameters)) + "\n")
            print (str("Parameters:").rjust(INDENTATION))
        
        for parameter in self.parameters:
            if self.fout:
                pprint.pprint(parameter.__dict__, stream=self.fout, indent="1")
            else:
                pprint.pprint(parameter.__dict__, indent="1")
             
        print( "\n" )
             
        if self.fout:
            self.fout.write( "\n" )
        else:
            print ("\n")
            
    def __init__( self ):
        self.burp = False
        self.surround_value = ""
        self.replace_value = ""
        self.fout = None
