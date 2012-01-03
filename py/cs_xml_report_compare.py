#cs_xml_report_compare.py
#
# A utility to compare two CodeSecure XML reports.
# 
# Right now, only works for benchmarking.
#
# Author: Cox Chen
#  Email: cox.chen@armorize.com
#

import sys, hashlib, time
from timeit import Timer
from difflib import SequenceMatcher as seqmatcher
from BeautifulSoup import BeautifulStoneSoup as bs

SEPARATOR_LENGTH = 43
CSI = "\x1B["
HIGH_COLOR = "35m"
CLOSE_COLOR = "0m"

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
        self.build_stats2()
    
    def _empty_stats(self):
        for vulnType in self.abstract['DELETE'].keys():
            self.stats[vulnType] = {'MATCHED': 0, 'INSERT': 0, 'DELETE': 0}
            self.diffAbstract['DELETE'][vulnType] = {}
        
        for vulnType in self.abstract['INSERT'].keys():
            self.diffAbstract['INSERT'][vulnType] = {}
            if vulnType not in self.stats.keys():
                self.stats[vulnType] = {'MATCHED': 0, 'INSERT': 0, 'DELETE': 0}
                self.diffAbstract['INSERT'][vulnType] = {}
    
    def build_stats2(self):
        self._empty_stats()
        
        for vulnType in self.abstract['INSERT'].keys():
            if self.abstract['DELETE'].has_key(vulnType):
                self.newCount += len(self.abstract['INSERT'][vulnType].keys())
                self.oldCount += len(self.abstract['DELETE'][vulnType].keys())
                
                newVulnKeys = self.abstract['INSERT'][vulnType].keys()
                oldVulnKeys = self.abstract['DELETE'][vulnType].keys()
                
                matchedKeys = set(oldVulnKeys).intersection(set(newVulnKeys))
                for matchedKey in matchedKeys:
                    self.abstract['INSERT'][vulnType][matchedKey]['status'] = 'MATCHED'
                    self.abstract['DELETE'][vulnType][matchedKey]['status'] = 'MATCHED'
                    self.stats[vulnType]['MATCHED'] += 1
                
                for key in self.abstract['INSERT'][vulnType].keys():
                    if self.abstract['INSERT'][vulnType][key]['status'] != 'MATCHED':
                        self.abstract['INSERT'][vulnType][key]['status'] = 'INSERT'
                        self.diffAbstract['INSERT'][vulnType][key] = self.abstract['INSERT'][vulnType][key]
                        self.stats[vulnType]['INSERT'] += 1
                for key in self.abstract['DELETE'][vulnType].keys():
                    if self.abstract['DELETE'][vulnType][key]['status'] != 'MATCHED':
                        self.abstract['DELETE'][vulnType][key]['status'] = 'DELETE'
                        self.diffAbstract['DELETE'][vulnType][key] = self.abstract['DELETE'][vulnType][key]
                        self.stats[vulnType]['DELETE'] += 1
    
    def build_stats(self):
        self._empty_stats()
        
        for vulnType in self.abstract['INSERT'].keys():
            if self.abstract['DELETE'].has_key(vulnType):
                self.newCount += len(self.abstract['INSERT'][vulnType].keys())
                self.oldCount += len(self.abstract['DELETE'][vulnType].keys())
                
                for key in self.abstract['INSERT'][vulnType].keys():
                    if self.abstract['DELETE'][vulnType].has_key(key):
                        self.abstract['DELETE'][vulnType][key]['status'] = 'MATCHED'
                        self.abstract['INSERT'][vulnType][key]['status'] = 'MATCHED'
                        self.stats[vulnType]['MATCHED'] += 1
                    else:
                        self.abstract['INSERT'][vulnType][key]['status'] = 'INSERT'
                        self.diffAbstract['INSERT'][vulnType][key] = self.abstract['INSERT'][vulnType][key]
                        self.stats[vulnType]['INSERT'] += 1
                
                deleteVulnKeys = filter(lambda x : self.abstract['DELETE'][vulnType][x]['status'] != 'MATCHED', self.abstract['DELETE'][vulnType].keys())
                self.stats[vulnType]['DELETE'] = len(deleteVulnKeys)
                for key in deleteVulnKeys:
                    self.abstract['DELETE'][vulnType][key]['status'] = 'DELETE'
                    self.diffAbstract['DELETE'][vulnType][key] = self.abstract['DELETE'][vulnType][key]
    
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
            print '-' * SEPARATOR_LENGTH
            for abstract in self.diffAbstract['INSERT'][vulnType].values():
                if abstract['status'] != 'MATCHED':
                    vulnCount += 1
                    print ' [{count}]'.format(count = vulnCount), abstract['tb']
        print
        if self.stats[vulnType]['DELETE'] > 0:
            print ' DEL: Disappeared vulnerabilities'
            print '-' * SEPARATOR_LENGTH
            for abstract in self.diffAbstract['DELETE'][vulnType].values():
                if abstract['status'] != 'MATCHED':
                    vulnCount += 1
                    print ' [{count}]'.format(count = vulnCount), abstract['tb']
        print '\n {vType} | INSERT:{ins:^3} | DELETE:{delete:^3} |\n'.format(vType = vulnType, ins = self.stats[vulnType]['INSERT'], delete = self.stats[vulnType]['DELETE'])
        if vulnCount > 0:
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
        theVuln = self.diffAbstract[catalog][vulnType].values()[int(vulnIdx) - 1]
        
        idxBase = 0
        if catalog == 'DELETE':
            idxBase = len(self.diffAbstract['INSERT'][vulnType])
        
        self.print_vuln_abstract_uuid(vulnIdx + idxBase, theVuln)
        self.print_vuln_abstract_tb(theVuln)
        
        counterCatalog = filter(lambda x: x != catalog, self.diffAbstract.keys())[0]
        counterIdxBase = 0
        if counterCatalog == 'DELETE':
            counterIdxBase = len(self.diffAbstract['INSERT'][vulnType])
        
        similarTBIdx = []
        counterIdx = counterIdxBase
        print
        for counterVuln in self.diffAbstract[counterCatalog][vulnType].values():
            counterIdx += 1
            sMatcher = seqmatcher(None, theVuln['tb'], counterVuln['tb'])
            if sMatcher.ratio() > 0.75:
                similarTBIdx.append(str(counterIdx))
                print '\t[{0}] {1:.1f}% {2}'.format(counterIdx, sMatcher.ratio() * 100, counterVuln['uuid'])
        
        print '\n  => Press d/D to show detailed traceback;'
        if len(similarTBIdx) > 0:
            print '  => enter index of similar vulnerability to compare;'
        print '  => or enter ANY KEY ELSE to continue:',
        userInput = raw_input().upper()
        
        inputProcessed = False
        if userInput == 'D':
            vulnDetail = self.soup[catalog].findAll('rd:vulnerability', uuid = theVuln['uuid'])[0]
            self.show_vuln_detail(vulnDetail, catalog)
            inputProcessed = True
        elif userInput in similarTBIdx:
            self.compare(vulnType, catalog, vulnIdx, counterCatalog, userInput)
            inputProcessed = True
        else:
            return
        self._press_any_key()
        self.show_vuln(vulnType, catalog, vulnIdx)
    
    def print_vuln_abstract_uuid(self, vulnIdx, theVuln):
        print '-' * SEPARATOR_LENGTH
        print '[{0}] UUID: {1}'.format(vulnIdx, theVuln['uuid'])
    
    def print_vuln_abstract_tb(self, theVuln, diffOpcodes = [], opcodeOffset = 1):
        print '-' * SEPARATOR_LENGTH
        
        if len(diffOpcodes) == 0:
            print theVuln['tb'].replace(';', '\n')
        else:
            augmentedVulnAbstract = ''
            for opcode in diffOpcodes:
                hStart = opcode[opcodeOffset]
                hEnd = opcode[opcodeOffset + 1]
                if opcode[0] == 'equal':
                    fragment = theVuln['tb'][hStart:hEnd]
                    
                else:
                    fragment = CSI + HIGH_COLOR + theVuln['tb'][hStart:hEnd].replace(';', '\n') + CSI + CLOSE_COLOR
                augmentedVulnAbstract += fragment
            print augmentedVulnAbstract.replace(';', '\n')
            
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
    
    def compare(self, vulnType, oCatalog, oIdx, cCatalog, cIdx):
        cIdxBase = 0
        oIdxBase = 0
        if cCatalog == 'DELETE':
            cIdxBase = len(self.diffAbstract['INSERT'][vulnType])
        else:
            oIdxBase = len(self.diffAbstract['INSERT'][vulnType])
        
        print '-' * SEPARATOR_LENGTH
        print 'Comparing {0}: {1}({2}) with {3}({4})'.format(vulnType, oIdx + oIdxBase, oCatalog, cIdx, cCatalog)
        
        oVuln = self.diffAbstract[oCatalog][vulnType].values()[int(oIdx) - 1]
        cVuln = self.diffAbstract[cCatalog][vulnType].values()[int(cIdx) - cIdxBase - 1]
        
        s = seqmatcher(None, oVuln['tb'], cVuln['tb'])
        self.print_vuln_abstract_uuid(oIdx + oIdxBase, oVuln)
        self.print_vuln_abstract_tb(oVuln, s.get_opcodes(), 1)
        self.print_vuln_abstract_uuid(cIdx, cVuln)
        self.print_vuln_abstract_tb(cVuln, s.get_opcodes(), 3)
    
    def _press_any_key(self):
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

def create_comparator(oldSoup, newSoup):
    comparator = XML_Report_Comparator(oldSoup, newSoup)
    return comparator

def main():
    oldXmlReport = sys.argv[1]
    newXmlReport = sys.argv[2]
    oldSoup = bs(file(oldXmlReport).read(), convertEntities=bs.HTML_ENTITIES)
    newSoup = bs(file(newXmlReport).read(), convertEntities=bs.HTML_ENTITIES)
    
    begin = time.time()
    comparator = create_comparator(oldSoup, newSoup)
    end = time.time()
    print '\n# took {0:.2f} secs to build the stats ...\n'.format(end - begin)
    
    comparator.show_options()

if __name__ == '__main__':
    main()
