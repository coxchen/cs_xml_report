#cs_xml_report_2_csv.py
#
# A utility for converting CodeSecure XML report into CSV format.
#
# Author: Cox Chen
#  Email: cox.chen@armorize.com
#

import sys, csv
from BeautifulSoup import BeautifulStoneSoup as bs

def main(xml_file):
    
    soup = bs(file(xml_file).read())
    vulns = soup.findAll('rd:vulnerability')
    
    csv_file = xml_file+'.csv'
    print 'converting', len(vulns), 'vulnerabilities into', csv_file
    csv_writer = csv.writer(open(csv_file, 'wb'), delimiter=',')
    
    csv_writer.writerow(['vuln_type', 'sink_file', 'line no'])
    
    for vuln in vulns:
        vuln_type = vuln['type']
        sink_file = soup.findAll('rd:file', id = vuln['sink'])[0]['path'] # get the sink file path
        snippet = vuln.findAll('rd:step')[-1].findAll('rd:snippet')[0]
        csv_writer.writerow([vuln_type, sink_file, snippet['line']])
    

if __name__ == '__main__':
    main(sys.argv[1])
