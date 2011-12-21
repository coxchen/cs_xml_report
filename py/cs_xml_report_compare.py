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

class Vulnerability:
    def __init__():
        pass

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
        sink_file_path = scannedFileDict[step['file']]
        stepSignature = step['type'] + ':' + sink_file_path + ':' + step['function'] + '#' + step.first()['line']
        signature.append(stepSignature)
    return ';'.join(signature)

def create_vulnerability_abstraction(aVuln, scannedFileDict):
    tbAbstract = create_tb_abstract(aVuln, scannedFileDict)
    md5Signature = hashlib.md5(tbAbstract).hexdigest()
    
    return {'uuid' : aVuln['uuid'],
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
                print vulnAbstract
                print vulnAbstractDict[vuln['type']][vulnAbstract['md5']], '\n'
                #raw_input()
            vulnAbstractDict[vuln['type']][vulnAbstract['md5']] = vulnAbstract
        else:
            vulnAbstractDict[vuln['type']] = {vulnAbstract['md5'] : vulnAbstract}
    
    return vulnAbstractDict

def main(oldXmlReport, newXmlReport):
    
    oldSoup = bs(file(oldXmlReport).read())
    newSoup = bs(file(newXmlReport).read())
    
    print '\n### extracting', oldXmlReport, '...\n'
    oldVulnAbstracts = extract_vulnerability_abstracts(oldSoup)
    print '\n\n### extracting', newXmlReport, '...\n'
    newVulnAbstracts = extract_vulnerability_abstracts(newSoup)
    
    # initialize the statistics
    vulnTypes = {}
    for vulnType in oldVulnAbstracts.keys():
        vulnTypes[vulnType] = {'MATCHED': 0, 'INSERT': 0, 'DELETE': 0}
    
    for vulnKey in newVulnAbstracts.keys():
        if vulnKey not in vulnTypes.keys():
            vulnTypes[vulnType] = {'MATCHED': 0, 'INSERT': 0, 'DELETE': 0}
    
    matchedCount = 0
    insertCount = 0
    deleteCount = 0
    
    newCount = 0
    oldCount = 0
    for vulnType in newVulnAbstracts.keys():
        if oldVulnAbstracts.has_key(vulnType):
            newCount += len(newVulnAbstracts[vulnType].keys())
            oldCount += len(oldVulnAbstracts[vulnType].keys())
            
            for vulnKey in newVulnAbstracts[vulnType].keys():
                if oldVulnAbstracts[vulnType].has_key(vulnKey):
                    oldVulnAbstracts[vulnType][vulnKey]['status'] = 'MATCHED'
                    newVulnAbstracts[vulnType][vulnKey]['status'] = 'MATCHED'
                    vulnTypes[vulnType]['MATCHED'] += 1
                    matchedCount += 1
                else:
                    #print ' INSERT:', newVulnAbstracts[vulnType][vulnKey]['tb']
                    newVulnAbstracts[vulnType][vulnKey]['status'] = 'INSERT'
                    vulnTypes[vulnType]['INSERT'] += 1
                    insertCount += 1
            
            deleteVulnKeys = filter(lambda x : oldVulnAbstracts[vulnType][x]['status'] != 'MATCHED', oldVulnAbstracts[vulnType].keys())
            vulnTypes[vulnType]['DELETE'] = len(deleteVulnKeys)
            deleteCount += len(deleteVulnKeys)
            for deleteVulnKey in deleteVulnKeys:
                oldVulnAbstracts[vulnType][deleteVulnKey]['status'] = 'DELETE'
    
    print '--------------------'
    print 'OLD:', len(oldSoup.findAll('rd:vulnerability')), ',', oldCount, 'unique paths'
    print 'NEW:', len(newSoup.findAll('rd:vulnerability')), ',', newCount, 'unique paths'
    print '--------------------'
    print 'MATCHED:', matchedCount
    print ' INSERT:', insertCount
    print ' DELETE:', deleteCount
    print
    
    print '{:>15} | MAT | INS | DEL |'.format('')
    print '{:>15}'.format(''), '-------------------'
    for vulnType in vulnTypes:
        print '{type:>15} | {match:^3} | {ins:^3} | {delete:^3} |'.format(type = vulnType, match = vulnTypes[vulnType]['MATCHED'], ins = vulnTypes[vulnType]['INSERT'], delete = vulnTypes[vulnType]['DELETE'])

if __name__ == '__main__':
    #main(sys.argv[1], sys.argv[2])
    
    main('gg301_r33648.xml', 'gg301_r33729.xml')
