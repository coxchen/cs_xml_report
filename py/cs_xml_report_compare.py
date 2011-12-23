#cs_xml_report_compare.py
#
# A utility to compare two CodeSecure XML reports.
# 
# Right now, only works for benchmarking.
#
# Author: Cox Chen
#  Email: cox.chen@armorize.com
#

import sys, hashlib
from BeautifulSoup import BeautifulStoneSoup as bs

SEPARATOR_LENGTH = 43
CSI = "\x1B["

class XML_Report_Comparator:
    def __init__(self, oldSoup, newSoup):
        self.soup = {}
        self.soup['DELETE'] = oldSoup
        self.soup['INSERT'] = newSoup
        self.scannedFile = {}
        self.scannedFile['DELETE'] = extract_scanned_files(oldSoup)
        self.scannedFile['INSERT'] = extract_scanned_files(newSoup)
        self.abstract = {}
        self.abstract['DELETE'] = extract_vulnerability_abstracts(oldSoup)
        self.abstract['INSERT'] = extract_vulnerability_abstracts(newSoup)
        
        self.diffAbstract = {'DELETE' : {}, 'INSERT': {}}
        self.oldCount = 0
        self.newCount = 0
        
        self.oldVulnCount = len(oldSoup.findAll('rd:vulnerability'))
        self.newVulnCount = len(newSoup.findAll('rd:vulnerability'))
        
        self.stats = {}
        self.build_stats()
    
    def build_stats(self):
        for vulnType in self.abstract['DELETE'].keys():
            self.stats[vulnType] = {'MATCHED': 0, 'INSERT': 0, 'DELETE': 0}
            self.diffAbstract['DELETE'][vulnType] = {}
        
        for vulnType in self.abstract['INSERT'].keys():
            self.diffAbstract['INSERT'][vulnType] = {}
            if vulnType not in self.stats.keys():
                self.stats[vulnType] = {'MATCHED': 0, 'INSERT': 0, 'DELETE': 0}
                self.diffAbstract['INSERT'][vulnType] = {}
        
        matchedCount = 0
        insertCount = 0
        deleteCount = 0
        
        for vulnType in self.abstract['INSERT'].keys():
            if self.abstract['DELETE'].has_key(vulnType):
                self.newCount += len(self.abstract['INSERT'][vulnType].keys())
                self.oldCount += len(self.abstract['DELETE'][vulnType].keys())
                
                for vulnKey in self.abstract['INSERT'][vulnType].keys():
                    if self.abstract['DELETE'][vulnType].has_key(vulnKey):
                        self.abstract['DELETE'][vulnType][vulnKey]['status'] = 'MATCHED'
                        self.abstract['INSERT'][vulnType][vulnKey]['status'] = 'MATCHED'
                        self.stats[vulnType]['MATCHED'] += 1
                        matchedCount += 1
                    else:
                        self.abstract['INSERT'][vulnType][vulnKey]['status'] = 'INSERT'
                        self.diffAbstract['INSERT'][vulnType][vulnKey] = self.abstract['INSERT'][vulnType][vulnKey]
                        self.stats[vulnType]['INSERT'] += 1
                        insertCount += 1
                
                deleteVulnKeys = filter(lambda x : self.abstract['DELETE'][vulnType][x]['status'] != 'MATCHED', self.abstract['DELETE'][vulnType].keys())
                self.stats[vulnType]['DELETE'] = len(deleteVulnKeys)
                deleteCount += len(deleteVulnKeys)
                for deleteVulnKey in deleteVulnKeys:
                    self.abstract['DELETE'][vulnType][deleteVulnKey]['status'] = 'DELETE'
                    self.diffAbstract['DELETE'][vulnType][deleteVulnKey] = self.abstract['DELETE'][vulnType][deleteVulnKey]
    
    def print_stats(self):
        print '-' * SEPARATOR_LENGTH
        print 'OLD:', self.oldVulnCount, ',', self.oldCount, 'unique paths'
        print 'NEW:', self.newVulnCount, ',', self.newCount, 'unique paths'
        print
        
        print ' IDX | {0:^15} | MAT | INS | DEL |'.format('V Type')
        print '-' * SEPARATOR_LENGTH
        for vulnType in self.stats.keys():
            print '{idx:^5}| {vType:>15} | {match:^3} | {ins:^3} | {delete:^3} |'.format(idx = self.stats.keys().index(vulnType) + 1, vType = vulnType, match = self.stats[vulnType]['MATCHED'], ins = self.stats[vulnType]['INSERT'], delete = self.stats[vulnType]['DELETE'])
    
    def show_options(self):
        self.print_stats()
        
        print '-' * SEPARATOR_LENGTH
        print ' => Enter vulnerability TYPE/IDX to view detail'
        print ' => Press q to quit:',
        userInput = raw_input().upper()
        
        if userInput == 'Q':
            sys.exit(0)
        elif self.stats.has_key(userInput):
            self.show_diff(userInput)
        elif userInput in [str(int(idx) + 1) for idx in range(len(self.stats.keys()))]:
            self.show_diff(self.stats.keys()[int(userInput) - 1])
        else:
            print '!@#$%'
        self.show_options()
    
    def show_diff(self, vulnType):
        vulnCount = 0
        if self.stats[vulnType]['INSERT'] > 0: 
            print '\n INS: Newly found vulnerabilities'
            print '-' * 30
            for abstract in self.diffAbstract['INSERT'][vulnType].values():
                if abstract['status'] != 'MATCHED':
                    vulnCount += 1
                    print ' #{count}'.format(count = vulnCount), abstract['tb']
        print
        if self.stats[vulnType]['DELETE'] > 0:
            print ' DEL: Disappeared vulnerabilities'
            print '-' * 30
            for abstract in self.diffAbstract['DELETE'][vulnType].values():
                if abstract['status'] != 'MATCHED':
                    vulnCount += 1
                    print ' #{count}'.format(count = vulnCount), abstract['tb']
        print '\n {vType} | INSERT:{ins:^3} | DELETE:{delete:^3} |\n'.format(vType = vulnType, ins = self.stats[vulnType]['INSERT'], delete = self.stats[vulnType]['DELETE'])
        print ' => Enter vulnerability index (1 - {count}) to view the traceback:'.format(count = vulnCount)
        print ' => Press ANY KEY ELSE to continue:',
        userInput = raw_input().upper()
        
        
        catalog = ''
        try:
            vulnIdx = int(userInput)
            if vulnIdx <= len(self.diffAbstract['INSERT'][vulnType].keys()):
                catalog = 'INSERT'
            elif vulnIdx <= vulnCount:
                catalog = 'DELETE'
                vulnIdx = vulnIdx - len(self.diffAbstract['INSERT'][vulnType].keys())
            self.show_vuln(vulnType, catalog, vulnIdx)
        except ValueError:
            return
        self.show_diff(vulnType)
    
    def show_vuln(self, vulnType, catalog, vulnIdx):
        uuid = self.diffAbstract[catalog][vulnType].values()[int(vulnIdx) - 1]['uuid']
        vuln = self.soup[catalog].findAll('rd:vulnerability', uuid = uuid)[0]
        
        print '-' * 30
        print 'UUID:' + self.diffAbstract[catalog][vulnType].values()[int(vulnIdx) - 1]['uuid']
        print '-' * 30
        tbAbstract = self.diffAbstract[catalog][vulnType].values()[int(vulnIdx) - 1]['tb']
        print tbAbstract.replace(';', '\n')
        
        print '\n  => Press d/D to show detailed traceback;'
        print '  => ANY KEY ELSE to continue:',
        userInput = raw_input().upper()
        if userInput == 'D':
            self.show_vuln_detail(vuln, catalog)
            
    def show_vuln_detail(self, vuln, catalog):
        for step in vuln.findAll('rd:step'):
            print '-' * 30
            print '', step['type'], self.scannedFile[catalog][step['file']],
            if step['function'] != '':
                print '[' + step['function'] + ']',
            print step.first()['line']
            print '-' * 30
            for snippet in step.findAll('rd:snippet'):
                print '\t' * int(step['indent']), snippet.contents[0]
        print '-' * 30
        print '\n => Press ANY KEY to continue:',
        raw_input()

def extract_scanned_files(aReportSoup):
    scannedFiles = aReportSoup.findAll('rd:file')
    scannedFileDict = {}
    for scanned in scannedFiles:
        scannedFileDict[scanned['id']] = scanned['path']
    return scannedFileDict

def create_tb_abstract(aVuln, scannedFileDict):
    signature = [aVuln['type'] + ':' + aVuln['source']]
    steps = aVuln.findAll('rd:step')
    for step in steps:
        sigList = [step['type'], scannedFileDict[step['file']]]
        if step['function'] != '':
            sigList.append(step['function'])
        stepSignature = ':'.join(sigList) + '#' + step.first()['line']
        signature.append(stepSignature)
    return ';'.join(signature)

def create_vulnerability_abstraction(aVuln, scannedFileDict):
    tbAbstract = create_tb_abstract(aVuln, scannedFileDict)
    md5Signature = hashlib.md5(tbAbstract).hexdigest()
    
    return {'vType' : aVuln['type'],
            'uuid' : aVuln['uuid'],
            'md5' : md5Signature,
            'tb' : tbAbstract,
            'status' : ''}

def extract_vulnerability_abstracts(aReportSoup):
    vulns = aReportSoup.findAll('rd:vulnerability')
    scannedFiles = extract_scanned_files(aReportSoup)
    
    vulnAbstractDict = {}
    for vuln in vulns:
        vulnAbstract = create_vulnerability_abstraction(vuln, scannedFiles)
        if vulnAbstractDict.has_key(vuln['type']):
            if vulnAbstractDict[vuln['type']].has_key(vulnAbstract['md5']):
                #print vulnAbstract
                #print vulnAbstractDict[vuln['type']][vulnAbstract['md5']], '\n'
                #raw_input()
                pass
            vulnAbstractDict[vuln['type']][vulnAbstract['md5']] = vulnAbstract
        else:
            vulnAbstractDict[vuln['type']] = {vulnAbstract['md5'] : vulnAbstract}
    
    return vulnAbstractDict

def main(oldXmlReport, newXmlReport):
    oldSoup = bs(file(oldXmlReport).read(), convertEntities=bs.HTML_ENTITIES)
    newSoup = bs(file(newXmlReport).read(), convertEntities=bs.HTML_ENTITIES)
    
    comparator = XML_Report_Comparator(oldSoup, newSoup)
    comparator.show_options()
    

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
    
    #main('gg301_r33648.xml', 'gg301_r33729.xml')
