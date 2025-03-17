#!/usr/bin/env python
#-*- coding: utf-8 -*-

import sys
import os
import argparse
import glob
from datetime import datetime
import logging
import re
import json

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

# Configure root level logger
logger = logging.getLogger(__name__)
ch = logging.StreamHandler()
logger.addHandler(ch)

# Parse float value from amount in a dictionary
def amt(d, i):
    return float(d[i].replace(",",""))

def write_results_to_file(payslips, outfile, format, field_names, quiffen_categories, employer_name):
    """
    Given a list of payslips, writes them to a file.

    :param payslips: List of dictionaries containing payslip data
    :param outfile: Destination
    :param format: choose QIF, CSV or JSON output, defaults to CSV
    :param field_names: List of field names to include in the output
    :param quiffen_categories: Dictionary of field names to Quiffen categories
    :param employer_name: Name of the employer for the QIF transactions
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
                fieldnames=field_names
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

        # Define categories for split
        categories = {field: quiffen.Category(name=category) for field, category in quiffen_categories.items()}
        for category in categories.values():
            qif.add_category(category)

        # Create transaction for each payslip
        for s in valid_slips:
            d = datetime.strptime(s['check_date'], '%m/%d/%Y')
            subs = []
            subs.append(quiffen.Transaction(payee = employer_name, date = d, category = categories['gross_pay'], amount = amt(s, 'gross_pay')))
            for field in field_names:
                if field in s and field != 'gross_pay' and field != 'net_pay' and field != 'check_date':
                    subs.append(quiffen.Transaction(payee = employer_name, date = d, category = categories[field], amount = -amt(s, field)))
            tr = quiffen.Transaction(
                payee = employer_name, 
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

def load_patterns(pattern_file):
    """
    Load regex patterns from a JSON file.
    :param pattern_file: Path to the JSON file containing regex patterns
    :return: Dictionary of compiled regex patterns, list of field names, and list of required field names
    """
    with open(pattern_file, 'r') as f:
        patterns = json.load(f)
    compiled_patterns = {p['field_name']: re.compile(p['pattern'], re.MULTILINE) for p in patterns}
    field_names = [p['field_name'] for p in patterns]
    required_field_names = [p['field_name'] for p in patterns if p['required']]
    quiffen_categories = {p['field_name']: p['quiffen_category'] for p in patterns}
    return compiled_patterns, field_names, required_field_names, quiffen_categories

def parse_payslip_page(body, patterns):
    """
    Parse PDF text from a pdftotext page and return dictionary of payslip data.
    :param body: Body text to parse.
    :param patterns: Dictionary of compiled regex patterns
    :return results: list of payslip data
    """

    results = {}
    for field, pattern in patterns.items():
        match = pattern.search(body)
        if match:
            results[field] = match.group(field)
            # replace blanks with a period, since some PDFs cannot translate periods
            results[field] = results[field].replace(" ", ".")

    return results

def parse_payslip_doc(pdf, patterns, required_field_names):
    """
    Parse PDF pages from pdftotext and return list of dictionary of payslip data.
    :param pdf: PDF object to parse.
    :param patterns: Dictionary of compiled regex patterns
    :param required_field_names: List of required field names
    :return results: list of payslip data
    """

    payslips = []
    pgnum = 0
    for page in pdf:
        payslip = {}
        payslip['data'] = page
        filename = 'page ' + str(pgnum) + ".txt"
        with open(filename, 'w') as f:
            print(page, file=f)
        payslip['status'] = 'empty'
        payslips.append(payslip)
        pgnum = pgnum + 1
    logger.info('Found %s pages', pgnum)

    for p in payslips:
        p['results'] = parse_payslip_page(p['data'], patterns)

        if all (k in p['results'] for k in required_field_names):
            p['status'] = 'valid'
            logger.debug('Valid payslip data found: %s' % p)
        else:
            p['status'] = 'invalid'
            logger.debug('Payslip fields missing from data: %s' % p)

    return payslips

def get_payslips_from_pdfs(pdfs, patterns, required_field_names):
    """
    Convert list of PDFs to text and scan them for payslip data.
    :param pdfs: List of valid PDF files to be parsed
    :param patterns: Dictionary of compiled regex patterns
    :param required_field_names: List of required field names
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
            payslips.extend(parse_payslip_doc(p, patterns, required_field_names))

    return payslips

def main(args):
    """
    The entrypoint for the Python script.
    :param args: Program arguments provided to the Python script
    :return: None
    """
    logger.info('- - - - P A Y S L I P - - - -')
    logger.debug('Invoked program with arguments: %s' % str(args))

    patterns, field_names, required_field_names, quiffen_categories = load_patterns(args.pattern_file)

    pdfs = get_pdf_files(args.input_dir, args.pattern)

    payslips = get_payslips_from_pdfs(pdfs, patterns, required_field_names)

    write_results_to_file(
        payslips,
        args.output_file,
        args.format.lower(),
        field_names,
        quiffen_categories,
        args.employer_name
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

    # The pattern file to load regex patterns from.
    parser.add_argument('-pf',
                        '--pattern-file',
                        required=True,
                        help='The JSON file containing regex patterns.')

    # The employer name for the QIF transactions.
    parser.add_argument('-e',
                        '--employer-name',
                        required=True,
                        help='The name of the employer for the QIF transactions.')

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
