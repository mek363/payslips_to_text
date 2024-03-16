#!/usr/bin/env python
#-*- coding: utf-8 -*-

import sys
import os
import argparse
import glob
from datetime import datetime
import logging
import re

import pdftotext

# Derived from payslips_to_text
# __author__ = 'Andrew Wurster'
# __license__ = 'GPL'
# __version__ = '1.0.0'
# __email__ = 'dev@awurster.com'
# __status__ = 'dev'

__author__ = 'Mat Kramer'
__license__ = 'GPL'
__version__ = '1.0.0'
__email__ = 'mat@vyperhelp.com'
__status__ = 'dev'

####### REGEX DEFINITIONS #######
# Examples of PDF raw text precede regular expressions:

# Gross Pay Pre Tax Deductions Employee Taxes Post Tax Deductions Net Pay
# Current 6,527.50 542.11 2,115.06 130.55 3,739.78
_RE_GROSS_PAY = re.compile('Current (?P<gross_pay>[\d\,\.]{1,}) [\d\,\.]{1,} [\d\,\.]{1,} [\d\,\.]{1,} [\d\,\.]{1,}')
_RE_NET_PAY = re.compile('Current [\d\,\.]{1,} [\d\,\.]{1,} [\d\,\.]{1,} [\d\,\.]{1,} (?P<net_pay>[\d\,\.]{1,})')

# Name Company Employee ID Pay Period Begin Pay Period End Check Date Check Number
# Matthew Kramer Medtronic Inc 312713 03/12/2022 03/25/2022 04/01/2022
_RE_CHECK_DATE = re.compile('Matthew Kramer Medtronic Inc 312713 \d\d\/\d\d\/\d\d\d\d \d\d\/\d\d\/\d\d\d\d (?P<check_date>\d\d\/\d\d\/\d\d\d\d)')

# Employee Taxes
# Description Amount YTD
# OASDI 397.13 2,794.53
# Medicare 92.88 653.56
# Federal Withholding 1,218.05 8,578.47
# State Tax - MN 407.00 2,865.00
_RE_OASDI = re.compile('OASDI (?P<oasdi>[\d\,\.]{1,})')
_RE_MEDICARE = re.compile('Medicare (?P<medicare>[\d\,\.]{1,})')
_RE_FED_WITHHOLD = re.compile('Federal Withholding (?P<fed_withhold>[\d\,\.]{1,})')
_RE_STATE_WITHHOLD = re.compile('State Tax - MN (?P<state_withhold>[\d\,\.]{1,})')

# Pre Tax Deductions
# Description Amount YTD
# 401(k) 391.65 2,741.55
# Dental Pre 55.38 387.66
# Medical Pre 95.08 665.56
_RE_401K = re.compile('401\(k\) (?P<k401>[\d\,\.]{1,})')
_RE_DENTAL = re.compile('Dental Pre (?P<dental>[\d\,\.]{1,})')
_RE_MEDICAL = re.compile('Medical Pre (?P<medical>[\d\,\.]{1,})')

# Post Tax Deductions
# Description Amount YTD
# Fitness Center 4.62 4.62
_RE_FITNESS = re.compile('Fitness Center (?P<fitness>[\d\,\.]{1,})')

# Fields that may be present
_FIELDNAMES = [
    'gross_pay',
    'net_pay',
    'check_date',
    'oasdi',
    'medicare',
    'fed_withhold',
    'state_withhold',
    'k401',
    'dental',
    'medical',
    'fitness'
]

# Fields that MUST be present
_REQUIRED_FIELDNAMES = [
    'gross_pay',
    'net_pay',
    'check_date'
]
####### END REGEX DEFINITIONS #######

# Configure root level logger
logger = logging.getLogger(__name__)
ch = logging.StreamHandler()
logger.addHandler(ch)

# Parse float value from amount in a dictionary
def amt(d, i):
    return float(d[i].replace(",",""))

def write_results_to_file(payslips, outfile, format):
    """
    Given a list of payslips, writes them to a file.

    :param payslips: List of dictionaries containing payslip data
    :param outfile: Destination
    :param format: choose QIF, CSV or JSON output, defaults to CSV
    :return: None
    """

    valid_slips = [p['results'] for p in payslips if p['status'] == 'valid']
    logger.info('Found %s valid payslip objects from %s total pages scanned.' % (len(valid_slips), len(payslips)))

    of = None
    if outfile:
        of = open(outfile, 'w')
    else:
        of = sys.stdout
        sys.stdout.write('\n')

    logger.info('Writing %s formatted results to %s\n' % (format, of.name))
    if format == 'csv':
        import csv
        if valid_slips:
            writer = csv.DictWriter(
                of,
                quoting=csv.QUOTE_ALL,
                fieldnames=_FIELDNAMES
            )
            writer.writeheader()
            rows = sorted(valid_slips,
                key=lambda d: datetime.strptime(d['check_date'], '%m/%d/%Y')
                )
            writer.writerows(rows)
        else:
            logger.error('No valid payslips found')
            sys.exit(1)

    elif format == 'qif':
        # Create a single transaction for each payslip, using subcategories
        import quiffen
        logger.info('Generating QIF transactions')

        # Create QIF object and define account
        qif = quiffen.Qif()
        acc = quiffen.Account(name = 'Checking')
        qif.add_account(acc)
        mdt = 'Medtronic'

        # Define categories for split
        cat_salary = quiffen.Category(name = 'Salary')
        cat_oasdi = quiffen.Category(name = 'Payroll Taxes - Social Security')
        cat_medicare = quiffen.Category(name = 'Payroll Taxes - Medicare')
        cat_fed_withhold = quiffen.Category(name = 'Payroll Taxes - Federal')
        cat_state_withhold = quiffen.Category(name = 'Payroll Taxes - State')
        cat_k401 = quiffen.Category(name = '[Medtronic 401k]')
        cat_dental = quiffen.Category(name = 'Pre Tax - Dent Ins')
        cat_medical = quiffen.Category(name = 'Pre Tax - Med Ins')
        cat_fitness = quiffen.Category(name = 'Fitness')
        qif.add_category(cat_salary)
        qif.add_category(cat_oasdi)
        qif.add_category(cat_medicare)
        qif.add_category(cat_fed_withhold)
        qif.add_category(cat_state_withhold)
        qif.add_category(cat_k401)
        qif.add_category(cat_dental)
        qif.add_category(cat_medical)
        qif.add_category(cat_fitness)

        # Create transaction for each payslip
        for s in valid_slips:
            d = datetime.strptime(s['check_date'], '%m/%d/%Y')
            subs = []
            subs.append(quiffen.Transaction(payee = mdt, date = d, category = cat_salary, amount = amt(s, 'gross_pay')))
            if 'oasdi' in s:
                subs.append(quiffen.Transaction(payee = mdt, date = d, category = cat_oasdi, amount = -amt(s, 'oasdi')))
            if 'medicare' in s:
                subs.append(quiffen.Transaction(payee = mdt, date = d, category = cat_medicare, amount = -amt(s, 'medicare')))
            if 'fed_withhold' in s:
                subs.append(quiffen.Transaction(payee = mdt, date = d, category = cat_fed_withhold, amount = -amt(s, 'fed_withhold')))
            if 'state_withhold' in s:
                subs.append(quiffen.Transaction(payee = mdt, date = d, category = cat_state_withhold, amount = -amt(s, 'state_withhold')))
            if 'k401' in s:
                subs.append(quiffen.Transaction(payee = mdt, date = d, category = cat_k401, amount = -amt(s, 'k401')))
            if 'dental' in s:
                subs.append(quiffen.Transaction(payee = mdt, date = d, category = cat_dental, amount = -amt(s, 'dental')))
            if 'medical' in s:
                subs.append(quiffen.Transaction(payee = mdt, date = d, category = cat_medical, amount = -amt(s, 'medical')))
            if 'fitness' in s:
                subs.append(quiffen.Transaction(payee = mdt, date = d, category = cat_fitness, amount = -amt(s, 'fitness')))
            tr = quiffen.Transaction(
                payee = mdt, 
                date = d,
                amount = amt(s, 'net_pay'),
                splits = subs)
            acc.add_transaction(tr, header='Bank')

        # write results to a file
        of.write(qif.to_qif())

    elif format == 'json':
        import json
        for l in valid_slips:
            of.write(f'{json.dumps(l)}\n')

    else:
        logger.warn('Unrecognised format %s.' % format)
        logger.debug('Dumping raw results for all payslips: %s' % payslips)
        sys.exit(1)

def get_pdf_files(input_dir, pattern):
    """
    Get a list of PDF files for parsing.
    :param input_dir: Directory to scan for input files
    :param pattern: Glob pattern to match for valid PDF files
    :return pdfs: List of valid PDF files to be parsed
    """
    pdfs = []
    for pdf in glob.glob(os.path.join(input_dir, pattern)):
        logger.debug('Found glob match: %s' % pdf)
        pdfs.append(pdf)

    if pdfs:
        logger.info('Found %s glob matches for PDFs to scan' % len(pdfs))
        return pdfs
    else:
        logger.error('Found no PDF glob matches for %s in %s' %
            (pattern, input_dir))
        sys.exit(1)

def parse_payslip_page(lines):
    """
    Parse PDF lines from a pdftotext page and return dictionary of payslip data.
    :param lines: List of lines to parse.
    :return results: list of payslip data
    """

    results = {}
    for line in lines:

        gross_pay = _RE_GROSS_PAY.search(line)
        net_pay = _RE_NET_PAY.search(line)
        check_date = _RE_CHECK_DATE.search(line)
        oasdi = _RE_OASDI.search(line)
        medicare = _RE_MEDICARE.search(line)
        fed_withhold = _RE_FED_WITHHOLD.search(line)
        state_withhold = _RE_STATE_WITHHOLD.search(line)
        k401 = _RE_401K.search(line)
        dental = _RE_DENTAL.search(line)
        medical = _RE_MEDICAL.search(line)
        fitness = _RE_FITNESS.search(line)

        if gross_pay:
            results['gross_pay'] = gross_pay.group('gross_pay')
        if net_pay:
            results['net_pay'] = net_pay.group('net_pay')
        if check_date:
            results['check_date'] = check_date.group('check_date')
        if oasdi:
            results['oasdi'] = oasdi.group('oasdi')
        if medicare:
            results['medicare'] = medicare.group('medicare')
        if fed_withhold:
            results['fed_withhold'] = fed_withhold.group('fed_withhold')
        if state_withhold:
            results['state_withhold'] = state_withhold.group('state_withhold')
        if k401:
            results['k401'] = k401.group('k401')
        if dental:
            results['dental'] = dental.group('dental')
        if medical:
            results['medical'] = medical.group('medical')
        if fitness:
            results['fitness'] = fitness.group('fitness')

    return results

def parse_payslip_doc(pdf):
    """
    Parse PDF pages from pdftotext and return list of dictionary of payslip data.
    :param pdf: PDF object to parse.
    :return results: list of payslip data
    """

    payslips = []
    pgnum = 0
    for page in pdf:
        payslip = {}
        payslip['data'] = []
        filename = 'page ' + str(pgnum) + ".txt"
        with open(filename, 'w') as f:
            print(page, file=f)
        payslip['data'].extend(page.split('\n'))
        payslip['status'] = 'empty'
        payslips.append(payslip)
        pgnum = pgnum + 1
    logger.info('Found %s pages', pgnum)

    for p in payslips:
        p['results'] = parse_payslip_page(p['data'])

        if all (k in p['results'] for k in _REQUIRED_FIELDNAMES):
            p['status'] = 'valid'
            logger.debug('Valid payslip data found: %s' % p)
        else:
            p['status'] = 'invalid'
            logger.debug('Payslip fields missing from data: %s' % p)

    return payslips

def get_payslips_from_pdfs(pdfs):
    """
    Convert list of PDFs to text and scan them for payslip data.
    :param pdfs: List of valid PDF files to be parsed
    :return payslips: List of dictionaries of valid payslip data
    """
    payslips = []
    for pdf in pdfs:
        with open(pdf,'rb') as pf:
            try:
                logger.info('Scanning %s', pf.name)
                p = pdftotext.PDF(pf, raw=True)
            except Exception as e:
                logger.debug('Exception scanning PDF document: %s' % str(e))
        if p:
            payslips.extend(parse_payslip_doc(p))

    return payslips

def main(args):
    """
    The entrypoint for the Python script.
    :param args: Program arguments provided to the Python script
    :return: None
    """
    logger.info('- - - - P A Y S L I P - - - -')
    logger.debug('Invoked program with arguments: %s' % str(args))

    pdfs = get_pdf_files(args.input_dir, args.pattern)

    payslips = get_payslips_from_pdfs(pdfs)

    write_results_to_file(
        payslips,
        args.output_file,
        args.format.lower()
        )

    sys.exit()


def parse_args():
    """
    Parses the program arguments.

    :return: An 'args' class containing the program arguments as attributes.
    """

    parser = argparse.ArgumentParser(
        description='Convert PDFs of payslips into QIF, CSV or JSON.')

    # The directory containing input PDFs.
    parser.add_argument('-i',
                        '--input-dir',
                        required=False,
                        default=os.getcwd(),
                        help='Location of PDF files containing payslip data (defaults to current directory.')

    # The input file pattern.
    parser.add_argument('-p',
                        '--pattern',
                        required=False,
                        default='*.pdf',
                        help='The input file names to match where payslip data resides (defaults to *.pdf).')

    # The output file to write results to, defaults to stdout.
    parser.add_argument('-o',
                        '--output-file',
                        required=False,
                        default=None,
                        help='The filename where output data will be written (defaults to stdout).')

    # Output formatting
    parser.add_argument('-f',
                        '--format',
                        required=False,
                        default='csv',
                        help='(csv|json) The output format for results (defaults to csv).')

    # Whether to print debug logging statements
    parser.add_argument('-v',
                        '--verbose',
                        required=False,
                        action='store_true',
                        help='Display verbose debugging output.')


    args = parser.parse_args()

    # If verbose mode is on, show DEBUG level logs and higher.
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug('Verbose logging enabled.')
    else:
        logger.setLevel(logging.INFO)

    return args


"""---- Entry point ----"""
if __name__ == '__main__':

    args = parse_args()
    main(args)
