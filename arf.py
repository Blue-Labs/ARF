#!/usr/bin/env python

__version__  = '1.15'
__author__   = 'David Ford'
__email__    = 'david@blue-labs.org'
__date__     = '2017-Jun-7 2:23E'
__license__  = 'Apache 2.0'

''' TODO:
    - 
'''

''' Abuse Reporting Format class for generating ARF reports and sending them to registered destinations
    References:
        https://en.wikipedia.org/wiki/Abuse_Reporting_Format
        RFC 5965 https://tools.ietf.org/html/rfc5965 (Feedback Loop; FBL)


WARNING: Some RIR operators (like ARIN) forbid usage of their dataset in commercial products. violate
         their ToS at your own risk if you put this module in a commercial product. I do not condone
         abuse of ToS


# as postgres user:
CREATE USER arf WITH ENCRYPTED PASSWORD 'xxx';
CREATE DATABASE abuse_contacts WITH OWNER arf;

# as arf
CREATE TABLE IF NOT EXISTS rirs (
  rir        TEXT NOT NULL PRIMARY KEY,
  search_url TEXT
);

CREATE TABLE IF NOT EXISTS contacts (
  netblock CIDR NOT NULL PRIMARY KEY,
  nicname  TEXT,
  rir      TEXT REFERENCES rirs,
  email    TEXT NOT NULL,
  UNIQUE (netblock)
);

import logging
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
import ipwhois
o = ipwhois.IPWhois('78.128.8.239', timeout=2, allow_permutations=False)
o.lookup_rdap(retry_count=1)


'''

import datetime
import netaddr
import smtplib
import dns.resolver
import logging
import pprint
import ipwhois
import traceback
import time
import string

from email.mime.text            import MIMEText
from email.mime.base            import MIMEBase
from email.mime.multipart       import MIMEMultipart
from email.message              import Message

from dns.resolver               import Resolver


# see http://www.iana.org/assignments/marf-parameters/marf-parameters.xml
_marf_types       = ('auth-failure', # unsolicited email or some other kind of email abuse
                     'abuse',        # email authentication failure report
                     'fraud',        # indicates some kind of fraud or phishing activity
                     'not-spam',     # indicates that the entity providing the report does not consider the message to be spam. This may be used to correct a message that was incorrectly tagged or categorized as spam
                     'other',        # any other feedback that does not fit into other registered types
                     'virus',        # report of a virus found in the originating message
                    )

_marf_parameters  = {'Arrival-Date':              {'multiple':False, },                          # date/time the original message was received
                     'Auth-Failure':              {'multiple':False, 'related':'auth-failure'},  # Type of email authentication method failure
                     'Authentication-Results':    {'multiple':True,  },                          # results of authentication check(s)
                     'Delivery-Result':           {'multiple':False, 'related':'auth-failure'},  # Final disposition of the subject message
                     'DKIM-ADSP-DNS':             {'multiple':False, 'related':'auth-failure'},  # Retrieved DKIM ADSP record
                     'DKIM-Canonicalized-Body':   {'multiple':False, 'related':'auth-failure'},  # Canonicalized body, per DKIM
                     'DKIM-Canonicalized-Header': {'multiple':False, 'related':'auth-failure'},  # Canonicalized header, per DKIM
                     'DKIM-Domain':               {'multiple':False, 'related':'auth-failure'},  # DKIM signing domain from "d=" tag
                     'DKIM-Identity':             {'multiple':False, 'related':'auth-failure'},  # Identity from DKIM signature
                     'DKIM-Selector':             {'multiple':False, 'related':'auth-failure'},  # Selector from DKIM signature
                     'DKIM-Selector-DNS':         {'multiple':False, 'related':'auth-failure'},  # Retrieved DKIM key record
                     'Feedback-Type':             {'multiple':False, },                          # registered feedback report type
                     'Incidents':                 {'multiple':False, },                          # unsigned 32bit integer expression of how many similar incidents are represented by this report
                     'Original-Mail-From':        {'multiple':False, },                          # email address used in the MAIL FROM portion of the original SMTP transaction
                     'Original-Rcpt-To':          {'multiple':True,  },                          # email address used in the RCPT TO portion of the original SMTP transaction
                     'Reported-Domain':           {'multiple':True,  },                          # a domain name the report generator considers to be key to the message about which a report is being generated
                     'Reported-URI':              {'multiple':True,  },                          # a URI the report generator considers to be key to the message about which a report is being generated
                     'Reporting-MTA':             {'multiple':False, },                          # MTA generating this report
                     'Source-IP':                 {'multiple':False, },                          # IPv4 or IPv6 address from which the original message was received
                     'SPF-DNS':                   {'multiple':False, 'related':'auth-failure'},  # Retrieved SPF record
                     'User-Agent':                {'multiple':False, },                          # name and version of the program generating the report
                     'Version':                   {'multiple':False, },                          # version of specification used
                     'Source-Port':               {'multiple':False, },                          # TCP source port from which the original message was received
                     'Identity-Alignment':        {'multiple':False, 'related':'auth-failure'},  # indicates whether the message about which a report is being generated had any identifiers in alignment as defined in [RFC7489]

                     'Original-Envelope-ID':      {'multiple':False, },                          # contains the envelope ID string used in the original [SMTP] transaction

}

class ARF():
    def __init__(self, subject, type_='abuse',
            reporting_username = 'abuse',
            reporting_domain   = 'blue-labs.org',
            smtpserver         = 'localhost',
            smtpport           = 587,
            logger             = None):

        if not type_ in _marf_types:
            raise ValueError('Report type must be in: {}'.format(_marf_types))

        # turn off everything but critical issues here so we're not polluting our logging views
        l = logging.getLogger("requests.packages.urllib3")
        l.setLevel(logging.WARNING)
        l.propagate = True

        # use a default logger with no log level
        if not logger:
            logger = logging.getLogger('ARF').log

        self.logger             = logger

        self.type_              = type_
        self.report_ts          = datetime.datetime.utcnow().strftime('%a, %d %b %Y %T +0000')
        self.reporting_username = reporting_username
        self.reporting_domain   = reporting_domain
        self.smtpserver         = smtpserver
        self.smtpport           = smtpport

        self.dbconn             = None
        self.text_suffix        = None

        headers = {'From':         '<{}@{}>'.format(reporting_username, reporting_domain),
                   'Subject':      'FW: '+subject,  # should be set as the same subject line in the offending email
                   'Date':         '{}'.format(self.report_ts),
                   'MIME-Version': '1.0',
                   }

        outer = MIMEMultipart(_subtype='report')
        for k,v in headers.items():
            outer[k] = v

        _part = MIMEText('')
        outer.attach(_part)
        self.part_greeting = _part

        _part = MIMEBase('message', 'report')
        outer.attach(_part)
        self.part_report = _part

        _part = Message()
        _part.add_header('Content-Type', 'message/rfc822; name="{}"'.format(subject))
        _part.add_header('Content-Disposition', 'attachment')
        outer.attach(_part)
        self.part_message = _part

        self.email = outer
        self.marf_parameters = {}
        self.abuse_contacts = []

        self.characterize('User-Agent', 'BlueLabs ARF v{}'.format(__version__))
        self.characterize('Arrival-Date', self.report_ts)
        self.characterize('Feedback-Type', self.type_)
        self.characterize('Version', '1')

        self.resolver = Resolver()
        self.resolver.search = []
        self.resolver.timeout = 5
        self.resolver.timeout = 10
        self.resolver.nameservers = ['8.8.8.8','8.8.4.4']


    def __str__(self):
        return self.email.as_string()

    def db_connect(self, uri):
        import psycopg2
        self.dbconn = psycopg2.connect(uri)

        with self.dbconn.cursor() as c:
            try:
                c.execute('SELECT count(1) FROM rirs')
                c.fetchone()
            except:
                self.dbconn.rollback()
                q = '''
CREATE TABLE IF NOT EXISTS rirs (
  rir        TEXT NOT NULL PRIMARY KEY,
  search_url TEXT
)'''
                c.execute(q);

                rirs= ('AFRINIC', 'APNIC', 'ARIN', 'LACNIC', 'RIPE NCC')
                q = '''
INSERT INTO rirs (rir)
VALUES      ( %s )
'''
                try:
                    c.executemany(q, [(v,) for v in rirs])
                except Exception as e:
                    print('DB error: {}'.format(e))

                self.dbconn.commit()


    def characterize(self, k, v):
        ''' Include a header and value about a specific offending unit, for example, known spam URLs

            Characterizing headers are machine readable units and applicable to specific report types
        '''

        marf_parameters = self.marf_parameters

        if not k in _marf_parameters:
            raise ValueError('Report Header is not in permitted values: {}'.format(_marf_parameters.keys()))

        mp = _marf_parameters[k]
        if not mp['multiple'] and k in marf_parameters:
            raise ValueError('Header type "{}" can only be included once'.format(k))

        if self.type_ == 'auth-failure' and not mp['related'] == 'auth-failure':
            raise ValueError('Header type "{}" can only be used with Type "auth-failure"'.format(k))

        if k == 'Source-IP':
            try:    v = netaddr.IPAddress(v)
            except: raise ValueError('Source IP must be a valid IP')
            marf_parameters[k] = str(v)
            return

        if k == 'Source-Port':
            try:
                if isinstance(v, str):
                    v = int(v, 10)
                if not 0 < v < 65536: raise ValueError
            except: raise ValueError('Source Port must be a valid port')
            marf_parameters[k] = str(v)
            return

        if not k in marf_parameters:
            if mp['multiple']:
                marf_parameters[k]=[]

        if mp['multiple']:
            if isinstance(v, list):
                for _v in v:
                    marf_parameters[k].append(_v)
            else:
                marf_parameters[k].append(v)
        else:
            marf_parameters[k]=v


    def add_text_notes(self, notes):
        if not notes:
            return

        if not isinstance(notes, list):
            notes = [notes]

        self.text_suffix = 'Reasons why this email was rejected. Duplicate lines indicate multiple infractions such as multiple recipient attempts:\n\n'

        for i,note in enumerate(notes, 1):
            self.text_suffix += '  {:> 3}: {}\n'.format(i,note)


    def set_message(self, msg, charset=None):
        self.maxlen = 100*1024

        payload=''

        if msg:
            if not charset:
                charset = msg.get_charset()

            payload = msg.as_bytes()

        if not payload:
            payload = 'This is an empty payload; our system blocked the email during initial SMTP greeting phase'

        self.payload_length = len(payload)
        self.part_message.set_payload(payload[:self.maxlen], charset)


    def generate(self):
        if not 'Incidents' in self.marf_parameters:
            self.marf_parameters['Incidents'] = str(1)   # default value

        missing_parms = []
        for rk in ('User-Agent','Arrival-Date','Feedback-Type','Incidents','Original-Mail-From',
                   'Original-Rcpt-To','Reported-Domain','Reporting-MTA','Source-IP','Source-Port',
                   'Version'):
            if not rk in self.marf_parameters:
                missing_parms.append(rk)
        if missing_parms:
            raise ValueError('The following MARF characterizing parameters are required: {}'.format(missing_parms))

        # replace the body of the first part
        _text = 'This is an email abuse report for an email message received from:\n'\
                '  Source IP: ${source_ip}:${source_port}\n  Timestamp: ${report_ts}\n\nFor more information about this format '\
                'please see http://www.mipassoc.org/arf/.\n\n'

        if self.text_suffix:
            _text += self.text_suffix

        if self.payload_length>self.maxlen:
            _text += '\nTo prevent DoS attacks this ARF has limited the attached email '\
                'body to no greater than 100K bytes in length. Contact '\
                '<${reporting_username}@${reporting_domain}> if you require the full body to analyze.'

        Tpl = string.Template(_text)
        try:
            _text = Tpl.safe_substitute({'source_ip':self.marf_parameters['Source-IP'],
                                    'source_port':self.marf_parameters['Source-Port'],
                                    'report_ts':self.marf_parameters['Arrival-Date'],
                                    'reporting_username':self.reporting_username,
                                    'reporting_domain':self.reporting_domain,
                                   }, )
        except:
            self.logger('Failed to fill in template:\n{!r}'.format(_text), console=True)
            self.logger('marf: {}'.format(self.marf_parameters), console=True)
            raise

        self.part_greeting.set_payload(_text)

        for k,v in sorted(self.marf_parameters.items()):
            if isinstance(v, list):
                for e in v:
                    self.part_report.add_header(k, e)
            else:
                self.part_report.add_header(k, v)

        self.part_report.set_payload('')


    nb_cache = {}
    def _nb_set_cache(self, registry, network, contacts):
        # store network block in local database
        self.logger('stash in NB cache: {}, {}, {}'.format(registry,network,contacts))
        self.nb_cache[network] = {'registry':registry, 'contacts':contacts}

        if not self.dbconn:
            return


    def _nb_get_cache(self, ip):
        # get contacts listed for smallest network this IP is found in
        # check local cache before trying the DB
        self.logger('find in NB cache: {}'.format(ip))
        for network in self.nb_cache:
            if ip in network:
                print('Recovered from cache: {}'.format(self.nb_cache[network]['contacts']))
                return self.nb_cache[network]['contacts']

        if not self.dbconn:
            return


    def find_abuse_contacts(self):
        # see http://www.abuse.net/using.phtml

        print('marf parms: {}'.format(self.marf_parameters))

        if not 'Reported-Domain' in self.marf_parameters and 'Source-IP' in self.marf_parameters:
            raise ValueError('Characterize with Reported-Domain and Source-IP before researching abuse contacts')

        rsv = self.resolver

        if 'Reported-Domain' in self.marf_parameters:
            for _reported_domain in self.marf_parameters['Reported-Domain']:
                self.logger('Researching {}'.format(_reported_domain), console=True)

                try:
                    # no ip addresses are looked up
                    netaddr.IPAddress(_reported_domain.strip('[]'))
                    continue
                except:
                    pass

                q  = _reported_domain+'.contacts.abuse.net.'

                rs = []
                try:
                    self.logger('starting DNS TXT lookup on {}'.format(q))
                    rs = rsv.query(q, 'TXT')
                except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.exception.Timeout): pass
                except Exception as e: print('ARF: problem resolving {}: {}'.format(q, e))

                for r in rs:
                    c = str(r).strip('"')
                    self.abuse_contacts.append(c)
                print('collected from abuse.net DNS: {}'.format(self.abuse_contacts))

        _cached_contacts = self._nb_get_cache(self.marf_parameters['Source-IP'])

        if not _cached_contacts:
            self.logger('IPWhois({})'.format(self.marf_parameters['Source-IP']), console=True)
            o = ipwhois.IPWhois(self.marf_parameters['Source-IP'], allow_permutations=False, timeout=3)

            retries = 3
            r = None

            while retries:
                retries -= 1

                try:
                    r = o.lookup_rdap(retry_count=1)
                    self.logger('got result: {}'.format(r))
                    break
                except ipwhois.exceptions.WhoisRateLimitError as e:
                    self.logger('Rate limit error encountered: {}'.format(e))
                    time.sleep(6)
                    continue
                except ipwhois.exceptions.HTTPLookupError:
                    self.logger('HTTPLookupError, sleeping 1sec')
                    time.sleep(1)
                    continue
                except ipwhois.exceptions.ASNRegistryError:
                    self.logger('ASNRegistryError, sleeping 6sec')
                    time.sleep(6)
                    continue
                except Exception as e:
                    self.logger(traceback.format_exc())
                    r = None
                    break

            contacts     = []

            if r:
                asn_registry = r['asn_registry']
                asn_network  = netaddr.IPNetwork(r['asn_cidr'])

                try:
                    for o in r['objects']:
                        if r['objects'][o]['roles']:
                            # limit our selection to just this object
                            if 'abuse' in r['objects'][o]['roles'] \
                                    and 'email' in r['objects'][o]['contact'] \
                                    and r['objects'][o]['contact']['email']:
                                for e in r['objects'][o]['contact']['email']:
                                    contacts.append(e['value'])

                    # no abuse contact found? be more general in our selection
                    if not contacts:
                        for o in r['objects']:
                            if 'email' in r['objects'][o]['contact'] \
                                    and r['objects'][o]['contact']['email']:
                                for e in r['objects'][o]['contact']['email']:
                                    contacts.append(e['value'])

                    # is it Microsoft? they avoid using the RDAP fields for the
                    # designed purposes and put everything in "remarks"
                    if 'MSFT' in r['objects']:
                        contacts.append('abuse@microsoft.com')

                except Exception as e:
                    print('i fucked up: {}'.format(e))
                    pprint.pprint(r)
            else:
                self.logger('ipwhois lookup is null?')

        else:
            self.logger('using cached lookup for {}'.format(self.marf_parameters['Source-IP']))
            contacts = _cached_contacts

        self.abuse_contacts += list(set(contacts))

        if contacts and not _cached_contacts:
            self._nb_set_cache(asn_registry, asn_network, contacts)

        rv = self.abuse_contacts and True or False
        self.logger('Discovered abuse contacts: {}, {}'.format(self.abuse_contacts, rv), console=True)

        return rv


    def set_smtp_auth_credentials(self, username, password):
        self.auth_username = username
        self.auth_password = password


    def send(self, *recipient, redirectTo=None):
        if not recipient:
            recipient = []

        if not isinstance(recipient, (list,tuple)):
            recipient = [recipient]

        recipient = self.abuse_contacts + recipient

        if not recipient:
            raise ValueError('No abuse contacts found for this domain and none specified in function call')

        self.email['To'] = recipient[0]
        for r in recipient[1:]:
            # this is broken...., .append?
            self.email['Cc'] = r

        # we set the To/CC headers, but redirect this
        if redirectTo:
            print('redirect to: {}'.format(redirectTo))
            recipient=redirectTo

        s = smtplib.SMTP(host=self.smtpserver, port=self.smtpport, timeout=60)
        s.starttls()
        s.ehlo(self.reporting_domain)
        if self.auth_username and self.auth_password:
            s.login(self.auth_username, self.auth_password)

        s.send_message(self.email, '{}@{}'.format(self.reporting_username, self.reporting_domain), recipient, mail_options=['SMTPUTF8','BODY=8BITMIME'])
        s.quit()

