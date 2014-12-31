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
        self.chain = False
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
    def setChain(self,chain):
        self.chain = chain
        
    # Getters
    def getDirective(self):
        return self.directive
    def getTargets(self):
        return self.targets
    def getActions(self):
        return self.actions
    def getOpName(self):
        return self.op_name
    def getOpParam(self):
        return self.op_param
    def getChain(self):
        return self.chain
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
            if target[0][0] == '!':
                    target[0] = target[0][1:]
            if target[0] not in self.targetOptions:
                print "Error: An unknown target was specified"
                #print target[0]
                #sys.exit(1)
        return 1
     
    def validateArgs(self,rule):
        if(rule.getOpName() not in self.operatorOptions):
            # Custom name we assigned in this program (so we can do BP checking
            if(rule.getOpName() !=  "Impliedrx"):
                print "Error an unknown Argument was specified"
                
                
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
            if action[0] == "chain":
                rule.setChain(True)
        return 1
    def validateIfChained(self,rule):
        # Must not specify disruptive action
        disruptive = ["allow","block","deny","drop","pass","pause","proxy","redirect"]
        metadata = ["id","rev","msg","severity","version","accuracy","maturity","logdata"]
        for act in rule.getActions():
            act = act.split(':')
            # Chains must not have phases
            if act[0] == "phase":
                print "Error: phases cannot be declared in chained rule"
                sys.exit(1)
            # Must not spec id,rev,msg,sev,version,accuracy,maturity,logdata
            if act[0] in metadata:
                print "Error: chained rules may not contain metadata actions"
                sys.exit(1)
            # Must not specify skip
            if act[0] == "skip":
                print "Error: Chained rules may not contain 'skip'"
                sys.exit(1)
            # Chains must not contain disruptive actions
            if act[0] in disruptive:
                print "Error: Chained rules may not contain disruptive actions"
                sys.exit(1)
    def validateBP(self,rule):
        if(rule.getDirective() != "SecRule"):
            print "Failed BP01: Directive must be camel case"

        # We prefer chain,id'123',phase:2, etc.
        if("chain" in rule.getActions()):
            if rule.getActions()[0] != "chain":
                print "Failed BP02: If 'chain' is present it should be the first action"
        for act in range(0,len(rule.getActions())):
            action = rule.getActions()[act].split(':')
            if(action[0] == "id" and (act != 0 or act != 1)):
                print "Failed BP03: The 'id' action must be the first action or follow 'chain'"
            hasHit = False
            try:
                if(action[0] == "phase" and rule.getActions[act -1].split(':')[0] != "id"):
                    hasHit = True
            except:
                    hasHit = True
            if hasHit == True:
                print "Failed BP04: the 'phase' action must follow the id"
        # Rule must specify phase and transform
        foundPhase = False
        foundTransform = False
        for act in rule.getActions():
            act = act.split(':')[0]
            if act == "phase":
                foundPhase = True
            if act == "t":
                foundTransform = True
        if foundPhase == False:
            print "Failed BP05: Each rule should specify a phase"
        if foundTransform == False:
            print "Failed BP06: Each rule should specify a transformation"
        # Check to make sure that t:none is specified first
        for act in rule.getActions():
            act = act.split(':')
            if act[0] == "t":
                if(act[1] != "none"):
                    print "Failed BP07: Each rule should start with t:none"
                break
        # Must specify regex is @rx
        if rule.getOpName() == "Impliedrx":
            print "Failed BP08: @rx should always be placed, not assumed"
        # Spacing checks we are gonna need the RAW STRING
        # We need to check that there are valid options for phase etc
        # No author tag
        # Must be quoted ( Which phases?)
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
    
    def readConf(self, filename):
        os.path.isfile(filename)
        rules = []
        f = open(filename,'rb')
        rule = ""
        appendNext = False
        for line in f.readlines():
            if line.lstrip().lower()[0:7] == "secrule" or appendNext == True:
                if(appendNext):
                    rules[-1] = rules[-1] + line
                else:
                    rules.append(line)
                if line.rstrip()[-1] == "\\":
                    appendNext = True
                else:
                    appendNext = False

        return rules    
        
    def parseRule(self,RuleString, previousRule):
        lineCheck = RuleString.rstrip().split('\n')
        if(len(lineCheck) > 1):
            RuleString = ""
            trimNext = False
            for line in lineCheck:
                if(trimNext == True):
                    line = line.lstrip()
                if(line.rstrip()[-1] == "\\"):
                    RuleString += line.rstrip()[:-1] 
                    trimNext = True
                else:
                    RuleString += line
        #print RuleString

        # To-Do find where this is in Apache and mirror it
        rule = shlex.split(RuleString)
        try:
            directive = rule[0]     
            targets = rule[1]
            args = rule[2]
        except IndexError:
            print "Error: A rule was detected that was missing data"
        try:
            actions = rule[3]
        # Todo: Some rules don't require all
        except IndexError:
            actions = None
        #print RuleString
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
        
        # Only undertake an action if it is there and we are not in a chain
       # if(previousRule != None):
        if(actions != None):
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

        if previousRule != None:
            if( not previousRule.getChain() ):
                # Make sure we have an ID
                foundID = False
                for act in rule.getActions():
                    if(act.split(':')[0] == "id"):
                        foundID = True
                if foundID == False:
                    print "The rule is missing an ID"
                    sys.exit(1)
        # If there is a previous rule and it was a chain... we must validate chained logic
        if previousRule != None:
            if(previousRule.getChain()):
                self.validateIfChained(rule)
        if(previousRule == None or previousRule.getChain() == False):
            self.validateBP(rule)
        else:
            print RuleString
        return rule
        # Validate chain

def main():
    example = """SecRule REQUEST_METHOD "@streq POST" "chain,phase:2,t:none,log,block,id:'2100000',msg:'SLR: Possible Elevation of Privilege Attack against .Net.',tag:'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3416',tag:'http://technet.microsoft.com/en-us/security/bulletin/ms11-100'"
"""
    example = """SecRule REQUEST_METHOD"""
    
    example2 = """SecRule REQUEST_METHOD:test"""
    
    example3 = """SecRule REQUEST_METHOD|REQUEST_METHOD"""
    
    example4 = """SecRule REQUEST_METHOD:Host|REQUEST_METHOD:Bob"""
    
    example5 = """SecRule REQUEST_METHOD:Host|REQUEST_METHOD:Bob "@streq POST" "chain,phase:2,t:none,log,block,id:'2100000',msg:'SLR: Possible Elevation of Privilege Attack against .Net.',tag:'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3416',tag:'http://technet.microsoft.com/en-us/security/bulletin/ms11-100'" """
    
    example6 = """
    SecRule REQUEST_LINE "^GET /$" "chain,phase:2,id:'981020',t:none,pass,nolog"
        SecRule REMOTE_ADDR "^(127\.0\.0\.|\:\:)1$" "chain,t:none"
                SecRule TX:'/PROTOCOL_VIOLATION\\\/MISSING_HEADER/' ".*" "chain,setvar:tx.missing_header=+1,setvar:tx.missing_header_%{tx.missing_header}=%{matched_var_name}"
                        SecRule TX:'/MISSING_HEADER_/' "TX\:(.*)" "capture,t:none,setvar:!tx.%{tx.1}"
    """
    
    #example2 = """SecRule REQUEST_METHOD:Host|REQUEST_METHOD:Bob "@streq POST" "chain,phase:2,t:none,log,block,id:'2100000',msg:'SLR: Possible Elevation of Privilege Attack against .Net.',tag:'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3416',tag:'http://technet.microsoft.com/en-us/security/bulletin/ms11-100'"
#"""
#    example3 = """SecRule REQUEST_METHOD:Host "@streq POST" "chain,phase:2,t:none,log,block,id:'2100000',msg:'SLR: Possible Elevation of Privilege Attack against .Net.',tag:'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3416',tag:'http://technet.microsoft.com/en-us/security/bulletin/ms11-100'"
#"""
    MyValidator = Validator(2.8)
    rules = MyValidator.readConf("modsecurity_crs_47_common_exceptions.conf")
    previousRule = None
    for rule in rules:
        previousRule = MyValidator.parseRule(rule,previousRule)

    
if __name__ == '__main__':
    main()
