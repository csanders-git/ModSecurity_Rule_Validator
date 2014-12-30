#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import sys
import os
import re
import cgi
import shlex # We are lazy
class Rule:
    def __init__(self):
        pass
    # Setters
    def setDirective(self, directive):
        self.directive = directive
    def setTargets(self, targets):
        self.targets = targets
    def setActions(self, actions):
        self.actions = actions
    def setOpName(self,op_name):
        self.op_name = op_name
    def setOpParam(self,op_param):
        self.op_param = op_param
    def setOpNegate(self,op_negate):
        self.op_negate = op_negate
    # Getters
    def getTargets(self):
        return self.targets
    def getActions(self):
        return self.actions
    def getOpName(self):
        return self.op_name
    def getOpParam(self):
        return self.op_param
# Rule validator
class Validator:

    targetOptions = ["ARGS","ARGS_COMBINED_SIZE","ARGS_GET","ARGS_GET_NAMES","ARGS_NAMES","ARGS_POST","ARGS_POST_NAMES","AUTH_TYPE","ENV","FILES","FILES_COMBINED_SIZE","FILES_NAMES","FILES_SIZES","FILES_TMPNAMES","FILES_TMP_CONTENT","GEO","GLOBAL","HIGHEST_SEVERITY","IP","MATCHED_VAR","MATCHED_VAR_NAME","MODSEC_BUILD","MULTIPART_FILENAME","MULTIPART_NAME","MULTIPART_BOUNDARY_QUOTED","MULTIPART_BOUNDARY_WHITESPACE","MULTIPART_DATA_AFTER","MULTIPART_DATA_BEFORE","MULTIPART_HEADER_FOLDING","MULTIPART_CRLF_LINE","MULTIPART_CRLF_LF_LINES","MULTIPART_LF_LINE","MULTIPART_MISSING_SEMICOLON","MULTIPART_INVALID_PART","MULTIPART_INVALID_QUOTING","MULTIPART_INVALID_HEADER_FOLDING","MULTIPART_FILE_LIMIT_EXCEEDED","MULTIPART_STRICT_ERROR","MULTIPART_UNMATCHED_BOUNDARY","PATH_INFO","QUERY_STRING","USERAGENT_IP","REMOTE_ADDR","REMOTE_HOST","REMOTE_PORT","REMOTE_USER","RESOURCE","REQBODY_PROCESSOR","REQBODY_ERROR","REQBODY_ERROR_MSG","REQUEST_BASENAME","FULL_REQUEST","FULL_REQUEST_LENGTH","REQUEST_BODY","REQUEST_BODY_LENGTH","MATCHED_VARS_NAMES","MATCHED_VARS","REQUEST_COOKIES","REQUEST_COOKIES_NAMES","REQUEST_FILENAME","REQUEST_HEADERS","REQUEST_HEADERS_NAMES","REQUEST_LINE","REQUEST_METHOD","REQUEST_PROTOCOL","REQUEST_URI","REQUEST_URI_RAW","UNIQUE_ID","STREAM_OUTPUT_BODY","STREAM_INPUT_BODY","RESPONSE_BODY","RESPONSE_CONTENT_LENGTH","RESPONSE_CONTENT_TYPE","RESPONSE_HEADERS","RESPONSE_HEADERS_NAMES","RESPONSE_PROTOCOL","RESPONSE_STATUS","RULE","SCRIPT_GID","SCRIPT_BASENAME","SCRIPT_FILENAME","SCRIPT_GROUPNAME","SCRIPT_MODE","SCRIPT_UID","SCRIPT_USERNAME","SERVER_ADDR","SERVER_NAME","SERVER_PORT","SESSION","SESSIONID","STATUS_LINE","URLENCODED_ERROR","INBOUND_DATA_ERROR","OUTBOUND_DATA_ERROR","USER","USERID","PERF_RULES","PERF_ALL","PERF_COMBINED","PERF_GC","PERF_LOGGING","PERF_PHASE1","PERF_PHASE2","PERF_PHASE3","PERF_PHASE4","PERF_PHASE5","PERF_SREAD","PERF_SWRITE","DURATION","TIME","TIME_DAY","TIME_EPOCH","TIME_HOUR","TIME_MIN","TIME_MON","TIME_SEC","TIME_WDAY","TIME_YEAR","TX","WEBAPPID","WEBSERVER_ERROR_LOG","XML"]
    
    operatorOptions = ["unconditionalMatch","noMatch","ipmatch","ipmatchFromFile","ipmatchf","rsub","rx","validateEncyption","pm","pmFromFile","pmf","within","contains","containsWord","detectSQLi","detectXSS","streq","beginsWith","endsWith","strmatch","validateDTD","validateSchema","verifyCC","verifyCPF","verifySSN","geoLookup","gsbLookup","rbl","inspectFile","fuzzy_hash","validateByteRange","validateUrlEncoding","validateUtf8Encoding","eq","gt","lt","le","ge"]

    transformOptions = ["none","base64Decode","base64Encode","compressWhitespace","cssDecode","escapeSeqDecode","sqlHexDecode","hexDecode","hexEncode","htmlEntityDecode","jsDecode","length","lowercase","md5","normalisePath","normalizePath","normalisePathWin","normalizePathWin","parityEven7bit","parityZero7bit","parityOdd7bit","removeWhitespace","removeNulls","replaceNulls","removeComments","removeCommentsChar","replaceComments","sha1","trim","trimLeft","trimRight","urlDecode","urlDecodeUni","Utf8Unicode","urlEncode","base64DecodeExt"]
    
    actionOptions = ["id","marker","rev","msg","logdata","accuracy","maturity","ver","severity","chain","log","nolog","auditlog","noauditlog","block","deny","status","drop","pause","redirect","proxy","pass","skip","skipAfter","allow","phase","t","ctl","xmlns","capture","sanitiseArg","sanitiseMatchedBytes","sanitizeMatchedBytes","sanitizeArg","sanitiseMatched","sanitizeMatched","sanitiseRequestHeader","sanitizeRequestHeader","sanitiseResponseHeader","sanitizeResponseHeader","setenv","setvar","expirevar","deprecatevar","initcol","setsid","setuid","setuid","exec","multiMatch","tag","prepend","append"]
   
   
    def __init__(self,ModSecVersion):
        if(ModSecVersion >= 3.0 or ModSecVersion <= 1.0):
            print "Error: Invalid ModSecurity version was supplied"
            sys.exit(1)
        self.version = ModSecVersion
        
    def validateDirective(self,directive):
        directive = (directive).lower()
        if(directive != "secrule"):
            print "Error: An invalid rule was detect, the rule did not begin with SecRule"
            sys.exit(1)
        return 1

    def validateTargets(self,rule):
        for target in rule.getTargets():
            target = target.split(':')
            if target[0] not in self.targetOptions:
                print "Error: An unknown target was specified"
                sys.exit(1)
        return 1
     
    def validateArgs(self,rule):
        if(rule.getOpName() not in self.operatorOptions):
            # Custom name we assigned in this program (so we can do BP checking
            if(rule.getOpName !=  "Impliedrx"):
                print "Error an unknown operator was specified"
                
                
    def validateActions(self,rule):
        for action in rule.getActions():
            action = action.split(':')
            if action[0] not in self.actionOptions:
                print "Error: An unknown action was specified: %s" % action[0]
                sys.exit(1)
            if action[0] == "t":
                if action[1] not in self.transformOptions:
                    print "Error: An unknown transformation was specified"
                    sys.exit(1)
        return 1
    def validateIfChained(self,targetSplit,argSplit,actionSplit,RuleString):
        pass
        # Must have actionID
        # If Chained::
            # Must not specify disruptive action
            # Must not specify skip after
            # Must not specify phase
            # Must not spec id,rev,msg,sev,version,accuracy,maturity,logdata
            # Must not specify skip
    def validateBP(self,targetSplit,argSplit,actionSplit,RuleString):
        # To-Do find where this is in Apache and mirror it
        rule = shlex.split(RuleString)
        directive = rule[0]
        targets = rule[1]
        args = rule[2]
        actions = rule[3]
        if(directive != "SecRule"):
            print "Failed BP01: Directive must be camel case"

            #print action
            # We prefer chain,id'123',phase:2, etc.
          #  if(i == 0):
          #      firstAction = action.split(":")[0]
          #      if(firstAction != "chain" and firstAction != "id"):
          #          print "Failed BP02: Rule must begin with chain or ID"
                        
        
        # No author tag
        # Must Specify phase
        # Must Specify atleast one transform
        # Always start by specifying t:none
        # Must not specify t:none if another transform is specified
        # Must be quoted ( Which phases?)
        # Must specify regex is @rx
        # Use @streq and @pm to avoid regex
        pass
    def parse_generic(self,RuleString,currentOffset=0):
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

    def parse_args(self,RuleString,rule):
        args = [0]
        op_negated = 0
        p = 0
        if(RuleString[p] == '!'):
            op_negated = 1
            p+=1
            while(RuleString[p] == ' ' and p != len(RuleString)):
                p+=1
         # Is there an explicit operator
        if(RuleString[p] != '@'):
            # This is implicity regex
            rule.setOpName("Impliedrx")
            rule.setOpParam(RuleString[p:])
        else:
            startp = p+1
            while(RuleString[p] != ' ' and p != len(RuleString)):
                p+=1
            rule.setOpName(RuleString[startp:p])
            # Skip over whitespace at the end
            while(RuleString[p] == ' '):
                p+=1
            rule.setOpParam(RuleString[p:])

    def parseRule(self,RuleString):
        # To-Do find where this is in Apache and mirror it
        rule = shlex.split(RuleString)
        try:
            directive = rule[0]
            
            targets = rule[1]
            args = rule[2]
            actions = rule[3]
        # Todo: Some rules don't require all
        except IndexError:
            print "Error: A rule was detected that was missing data"
        rule = Rule()
        
        rule.setDirective(directive)
        self.validateDirective(directive)

   
        # Follow same logic as ModSec
        targetSplit = self.parse_generic(targets)
        tempTargets = []
        if(targetSplit != -1):
            for i in range(0,len(targetSplit)):
                if(i != len(targetSplit)-1):
                    tempTarget = targets[targetSplit[i]:targetSplit[i+1]]
                    if(tempTarget[0] == '|'):
                        tempTarget = tempTarget[1:]
                    tempTargets.append(tempTarget)
        rule.setTargets(tempTargets)
        self.validateTargets(rule)
        
        self.parse_args(args,rule)
      
        self.validateArgs(rule)
        
        actionSplit = self.parse_generic(actions)
        tempActions = []
        if(actionSplit != -1):            
            for i in range(0,len(actionSplit)):
                if(i != len(actionSplit)-1):
                    tempAction = actions[actionSplit[i]:actionSplit[i+1]]
                    if(tempAction[0] == ','):
                        tempAction = tempAction[1:]
                    tempActions.append(tempAction)
        rule.setActions(tempActions)
        
        self.validateActions(rule)
        
        # Make sure we have an ID
        foundID = False
        for act in rule.getActions():
            if(act.split(':')[0] == "id"):
                foundID = True
        if foundID == False:
            print "The rule is missing an ID"
            sys.exit(1)
        

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

    
if __name__ == '__main__':
    main()
