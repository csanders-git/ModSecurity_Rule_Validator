#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import sys
import os
import re
import cgi
import shlex # We are lazy

# Rule validator
class Validator:
    def __init__(self,ModSecVersion):
        if(ModSecVersion >= 3.0 or ModSecVersion <= 1.0):
            print "Error: Invalid ModSecurity version was supplied"
            sys.exit(1)
        self.version = ModSecVersion
    def validate(slef,ParsedRule):
        # Must be SecRule
        # Must specify ID
        # Must Specify phase
        # Must Specify atleast one transform
        # Must not specify t:none if another transform is specified
        # Must be quoted ( Which phases?)
        # Must specify regex is @rx
        pass
    def parse_target(self,RuleString,currentOffset=0):
        targets = [currentOffset]
        name = ""
        p = currentOffset
        while(p != len(RuleString)):
            # Ignore the whitespace after SecRule
            while RuleString[p] == ' ':
                p += 1
            # We are at the start of a target
            while(p != len(RuleString) and RuleString[p] != '|' and RuleString[p] != ':' and RuleString[p] != ',' and RuleString[p] != ' '):
                p += 1

            # We must put this here because its ugly to read past the end of an array in python
            if(p==len(RuleString)):
                targets.append(p)
                return targets
            if(RuleString[p] != ':'):
                targets.append(p)
                if(RuleString[p] == ' ' ):
                    p+=1
                if(RuleString[p] == ',' or RuleString[p] == '|'):
                    p+=1
                    continue
                print "Error: Unexcpected char found"
                return -1 
            # Otherwise we have a parameter
            # Skip over the colon
            p += 1
            # Allow empty values
            if(p == len(RuleString)):
                targets.append(p)
                return targets
            # Move over the separator
            if(RuleString[p] == ',' and RuleString[p] == '|'):
                targets.append(p)
                p+=1
                continue
            if(RuleString[p] == '\''):
                # skip the opening quote
                p+=1
                while True:
                    if p == len(RuleString):   
                        print "Error Missing Quote"
                        return -1
                    else:
                        if(RuleString[p] == '\\'):
                            if(p == len(RuleString) or RuleString[p+1] != '\'' and RuleString[p+1] != '\\'):
                                print "Error invalid quote pair"
                                return -1
                            p+=1
                        else:
                            if(RuleString[p] == '\''):
                                p+=1
                                break
                            else:
                                p+=1
            # Unquoted value
            else:
                while(p != len(RuleString) and RuleString[p] != ',' and RuleString[p] != '|' and RuleString[p] != ' '):
                    p += 1
            targets.append(p)
            if(p != len(RuleString)):
                while(RuleString[p] == ' ' or RuleString[p] == ',' or RuleString[p] == '|'):
                    p+=1
        return targets

    def parse_args(self,RuleString,currentOffset=0):
        args = [currentOffset]
        op_negated = 0
        op_name = ""
        op_param = -1
        p = currentOffset
        if(RuleString[p] == '!'):
            op_negated = 1
            p+=1
            while(RuleString[p] == ' ' and p != len(RuleString)):
                p+=1
         # Is there an explicit operator
        if(RuleString[p] != '@'):
            # This is implicity regex
            opname = "rx"
            op_param = p
        else:
            startp = p+1
            while(RuleString[p] != ' ' and p != len(RuleString)):
                p+=1
            opname = RuleString[startp:p]
            # Skip over whitespace at the end
            while(RuleString[p] == ' '):
                p+=1
            op_param = p

    def parseRule(self,RuleString):
        # To-Do find where this is in Apache and mirror it
        rule = shlex.split(RuleString)
        try:
            indicator = rule[0]
            targets = rule[1]
            args = rule[2]
            transformations = rule[3]
            actions = rule[4]
        except IndexError:
            print "Index Error"
        # The term 'SecRule' is actually case insensative
        word = (indicator).lower()
        if(word != "secrule"):
            print "Error: An invalid rule was detect, the rule did not begin with SecRule"
            sys.exit(1)
        # Follow same logic as ModSec
        targetSplit = self.parse_target(targets)
        if(targetSplit != -1):
            for i in range(0,len(targetSplit)):
                if(i != len(targetSplit)-1):
                    print targets[targetSplit[i]:targetSplit[i+1]]
        #print RuleString[firstSpace:length-firstSpace]
        argsSplit = self.parse_args(args)
        
        
        
class Rule:
    def __init__(self):
        pass
   
def main():
    example = """SecRule REQUEST_METHOD "@streq POST" "chain,phase:2,t:none,log,block,id:'2100000',msg:'SLR: Possible Elevation of Privilege Attack against .Net.',tag:'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3416',tag:'http://technet.microsoft.com/en-us/security/bulletin/ms11-100'"
"""
    example = """SecRule REQUEST_METHOD"""
    
    example2 = """SecRule REQUEST_METHOD:test"""
    
    example3 = """SecRule REQUEST_METHOD|REQUEST_METHOD"""
    
    example4 = """SecRule REQUEST_METHOD:Host|REQUEST_METHOD:Bob"""
    
    example5 = """SecRule REQUEST_METHOD:Host|REQUEST_METHOD:Bob "@streq POST" "chain,phase:2,t:none,log,block,id:'2100000',msg:'SLR: Possible Elevation of Privilege Attack against .Net.',tag:'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3416',tag:'http://technet.microsoft.com/en-us/security/bulletin/ms11-100'" """
    
    #example2 = """SecRule REQUEST_METHOD:Host|REQUEST_METHOD:Bob "@streq POST" "chain,phase:2,t:none,log,block,id:'2100000',msg:'SLR: Possible Elevation of Privilege Attack against .Net.',tag:'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3416',tag:'http://technet.microsoft.com/en-us/security/bulletin/ms11-100'"
#"""
#    example3 = """SecRule REQUEST_METHOD:Host "@streq POST" "chain,phase:2,t:none,log,block,id:'2100000',msg:'SLR: Possible Elevation of Privilege Attack against .Net.',tag:'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3416',tag:'http://technet.microsoft.com/en-us/security/bulletin/ms11-100'"
#"""
    MyValidator = Validator(2.8)
    MyValidator.parseRule(example5)
    #MyValidator.parseRule(example3)
    
if __name__ == '__main__':
    main()
