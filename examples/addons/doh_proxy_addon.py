"""
This is mean to be a DNS over HTTPS proxy.
It intercepts DNS over HTTPS requests and forwards them to another resolver (by default the system resolver)
and returns the response.

It loads a blacklist of IPs and hostnames that are known to serve DNS over HTTPS requests.
It also uses headers, query params, and paths to detect DoH queries.
"""
import base64
import functools
import json
import os
import re
import socket
import urllib.request
import asyncio
from typing import List, Tuple, Iterator

import dns.message
import dns.query
import dns.rdatatype
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.resolver

from mitmproxy import ctx, http
from mitmproxy.options import Options
from mitmproxy.log import Log, LogEntry

class Logger(Log):
    LOG_TAG = '[doh proxy]'

    def __call__(self, text, level="info"):
        text = '{} {}'.format(Logger.LOG_TAG, text)
        asyncio.get_event_loop().call_soon(
            self.master.addons.trigger, "log", LogEntry(text, level)
        )

logger = Logger(master=ctx.log.master)

# filename we'll save the blacklist to so we don't have to re-generate it every time
blacklist_filename = 'blacklist.json'

# additional hostnames to block
additional_doh_names: List[str] = [
    'dns.google.com'
]

# additional IPs to block
additional_doh_ips: List[str] = [

]


def get_doh_providers() -> Iterator[dict]:
    """
    Scrape a list of DoH providers from curl's wiki page.

    :return: a generator of dicts containing information about the DoH providers
    """
    https_url_re = re.compile(r'https://'
                              r'(?P<hostname>[0-9a-zA-Z._~-]+)'
                              r'(?P<port>:[0-9]+)?'
                              r'(?P<path>[0-9a-zA-Z._~/-]+)?')

    provider_re = re.compile(r'(\[([^\]]+)\]\(([^)]+))\)|(.*)')
    # URLs that are not DoH URLs
    do_not_include = ['my.nextdns.io', 'blog.cloudflare.com']
    found_table = False
    with urllib.request.urlopen('https://raw.githubusercontent.com/wiki/curl/curl/DNS-over-HTTPS.md') as fp:
        for line in fp:
            line = line.decode()
            if line.startswith('|'):
                if not found_table:
                    found_table = True
                    continue
                cols = line.split('|')
                provider_col = cols[1].strip()
                website = None
                provider_name = None
                matches = provider_re.findall(provider_col)
                if matches[0][3] != '':
                    provider_name = matches[0][3]
                if matches[0][1] != '':
                    provider_name = matches[0][1]
                if matches[0][2] != '':
                    website = matches[0][2]
                if provider_name is not None:
                    provider_name = re.sub(r'([^[]+)\s?(.*)', r'\1', provider_name)
                    while provider_name[-1] == ' ':
                        provider_name = provider_name[:-1]
                url_col = cols[2]
                doh_url_matches = https_url_re.findall(url_col)
                if len(doh_url_matches) == 0:
                    continue
                else:
                    for doh_url in doh_url_matches:
                        if doh_url[0] in do_not_include:
                            continue
                        yield {
                            'name': provider_name,
                            'website': website,
                            'url': 'https://{}{}{}'.format(doh_url[0],
                                                           ':{}'.format(doh_url[1])
                                                           if len(doh_url[1]) != 0
                                                           else '', doh_url[2]),
                            'hostname': doh_url[0],
                            'port': doh_url[1] if len(doh_url[1]) != 0 else '443',
                            'path': doh_url[2],
                        }
            if found_table and line.startswith('#'):
                break
    return


def get_ips(hostname: str) -> List[str]:
    """
    Lookup all A and AAAA records for given hostname

    :param hostname: the name to lookup
    :return: a list of IP addresses returned
    """
    default_nameserver = dns.resolver.Resolver().nameservers[0]
    ips = list()
    rdtypes = [dns.rdatatype.A, dns.rdatatype.AAAA]
    for rdtype in rdtypes:
        q = dns.message.make_query(hostname, rdtype)
        r = dns.query.udp(q, default_nameserver)
        if r.flags & dns.flags.TC:
            r = dns.query.tcp(q, default_nameserver)
        for a in r.answer:
            for i in a.items:
                if isinstance(i, dns.rdtypes.IN.A.A) or isinstance(i, dns.rdtypes.IN.AAAA.AAAA):
                    ips.append(str(i.address))
    return ips


def load_blacklist() -> Tuple[List[str], List[str]]:
    """
    Load a tuple containing two lists, in the form of (hostnames, ips).
    It will attempt to load it from a file, and if that file is not found,
    it will generate the blacklist and save it to a file.

    :return: a ``tuple`` of two lists containing the hostnames and IP addresses to blacklist
    """
    if os.path.isfile(blacklist_filename):
        with open(blacklist_filename, 'r') as fp:
            j = json.load(fp)
        doh_hostnames, doh_ips = j['hostnames'], j['ips']
    else:
        logger.info('skipping blacklist loading for now')
        return [], []
        # doh_hostnames = list([i['hostname'] for i in get_doh_providers()])
        # doh_ips = list()
        # for hostname in doh_hostnames:
        #     ips = get_ips(hostname)
        #     doh_ips.extend(ips)
    doh_hostnames.extend(additional_doh_names)
    doh_ips.extend(additional_doh_ips)
    with open(blacklist_filename, 'w') as fp:
        obj = {
            'hostnames': doh_hostnames,
            'ips': doh_ips
        }
        json.dump(obj, fp=fp)
    return doh_hostnames, doh_ips


# load DoH hostnames and IP addresses to block
logger.info('Loading DoH blacklist...')
doh_hostnames, doh_ips = load_blacklist()

# convert to sets for faster lookups
doh_hostnames = set(doh_hostnames)
doh_ips = set(doh_ips)

logger.info('Loaded {} hostnames and {} IP addresses into DoH blacklist'.format(len(doh_hostnames), len(doh_ips)))


class DohHandler:
    def up(self):
        pass

    def down(self):
        pass

    def handle(self, flow: http.HTTPFlow):
        pass

    @staticmethod
    def decode_dns_request(flow: http.HTTPFlow) -> dns.message.Message:
        """
        Parse a DNS query from an HTTP request/flow

        :param flow: the flow to extract the DNS request from
        :return: a :class:`dns.message.Message`
        :raise ValueError: If the request method was anything either than GET or POST
        """
        if flow.request.method == 'GET':
            if 'dns' in flow.request.query:
                b64encoded = flow.request.query['dns']
                padding_needed = 4 - len(b64encoded) % 4
                if padding_needed != 4:
                    b64encoded += '=' * padding_needed
                wire = base64.urlsafe_b64decode(b64encoded)
                return dns.message.from_wire(wire)
        elif flow.request.method == 'POST':
            wire = flow.request.content
            return dns.message.from_wire(wire)
        else:
            raise ValueError('Expecting request method to be GET or POST, got {} instead'.format(flow.request.method))


class ProxyDohHandler(DohHandler):
    def __init__(self, upstream_addr: str, upstream_port: int, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._upstream_addr = upstream_addr
        self._upstream_port = upstream_port
        self._upstream_sock = None

    def up(self):
        # setup client socket for upstream server
        af = dns.inet.af_for_address(self._upstream_addr)
        self._upstream_sock = socket.socket(af, socket.SOCK_DGRAM, 0)
        self._upstream_sock.connect((self._upstream_addr, self._upstream_port))

    def down(self):
        try:
            self._upstream_sock.close()
        except Exception:
            pass

    def handle(self, flow: http.HTTPFlow) -> None:
        """
        Decode DNS query from HTTP flow, send it to upstream DNS server, and return HTTP response containing answer

        :param flow: the HTTP request to proxy
        """
        q = self.decode_dns_request(flow)
        q_wire = q.to_wire()
        n_sent = self._upstream_sock.send(q_wire)
        assert n_sent == len(q_wire)
        r_wire = self._upstream_sock.recv(65536)
        headers = {'Content-Type': 'application/dns-message'}
        if 'origin' in flow.request.headers:
            headers['Access-Control-Allow-Origin'] = flow.request.headers['origin']
        else:
            headers['Access-Control-Allow-Origin'] = '*'

        flow.response = http.HTTPResponse.make(
            status_code=200,  # (optional) status code
            content=r_wire,
            headers=headers  # (optional) headers
        )

class BlockDohHandler(DohHandler):
    def handle(self, flow: http.HTTPFlow) -> None:
        flow.kill()

class LogDohHandler(DohHandler):
    def handle(self, flow: http.HTTPFlow) -> None:
        query = self.decode_dns_request(flow)
        logger.info(
            'query for {} from {} to {}'.format(query.question[0].name.to_text(), flow.client_conn.address.domain,
                                                flow.server_conn.address.domain))

LOG_DOH = 'log'
BLOCK_DOH = 'block'
PROXY_DOH = 'proxy'
NOTHING = 'nothing'

doh_handlers = {
    LOG_DOH: LogDohHandler,
    BLOCK_DOH: BlockDohHandler,
    PROXY_DOH: ProxyDohHandler,
    NOTHING: DohHandler
}
doh_handler_name = os.getenv('DOH_HANDLE', NOTHING)
doh_handler = doh_handlers.get(doh_handler_name)
if doh_handler is None:
    raise ValueError('Environment variable DOH_ACTION is set to something invalid \"{}\". Must be one of {}'.format(
        doh_handler_name, list(doh_handlers.keys())
    ))
_default_nameserver = dns.resolver.Resolver().nameservers[0]
if doh_handler_name == PROXY_DOH:
    ip = os.getenv('DOH_PROXY_UPSTREAM_IP', _default_nameserver)
    port = os.getenv('DOH_PROXY_UPSTREAM_PORT', 53)
    doh_handler_init = functools.partial(doh_handler, ip, port)
else:
    doh_handler_init = doh_handler


# noinspection PyArgumentList
class DohAddon:
    def __init__(self):
        self.doh_handler = doh_handler_init()

    def load(self, loader: Options):
        loader.add_option(
            name='dohhandler',
            typespec=str,
            default=NOTHING,
            help='What do do when a DNS over HTTPS query is detected',
            choices=list(doh_handlers.keys()),
        )
        loader.add_option(
            name='dohproxyaddr',
            typespec=str,
            default=_default_nameserver,
            help='Address of upstream DNS to proxy requests to',
        )
        loader.add_option(
            name='dohproxyport',
            typespec=int,
            default=53,
            help='Port to proxy DNS requests to. Default is 53'
        )

    def configure(self, updates):
        if 'dohhandler' in updates:
            if ctx.options.dohhandler is not None:
                logger.info('Setting up DoH handler...')
                self.doh_handler.down()
                if ctx.options.dohhandler == PROXY_DOH:
                    self.doh_handler = ProxyDohHandler(ctx.options.dohproxyaddr, ctx.options.dohproxyport)
                else:
                    self.doh_handler = doh_handlers[ctx.options.dohhandler]()
                self.doh_handler.up()
                logger.info('DoH handler up and running!')

    def handle_doh(self, flow: http.HTTPFlow) -> None:
        if isinstance(self.doh_handler, DohHandler):
            self.doh_handler.handle(flow)

    def request(self, flow: http.HTTPFlow) -> None:
        # if the request looks like a DNS over HTTPS query, call self.proxy_doh_query()
        for check in DohAddon.doh_query_checks():
            is_doh = check(flow)
            if is_doh:
                logger.info("DNS over HTTPS request detected because '{}'".format(
                    ' '.join(check.__name__[1:].split('_'))))
                if flow.request.method == 'OPTIONS':
                    self.handle_doh_options_request(flow)
                    break

                try:
                    self.doh_handler.handle(flow)
                except Exception as e:
                    logger.error('Error occurred while proxying DoH query: {}'.format(e))
                finally:
                    break

    @staticmethod
    def handle_doh_options_request(flow: http.HTTPFlow) -> None:
        headers = {
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Methods': 'GET, POST',
        }
        if 'Origin' in flow.request.headers:
            headers['Access-Control-Allow-Origin'] = flow.request.headers['Origin']
        else:
            headers['Access-Control-Allow-Origin'] = '*'

        flow.response = http.HTTPResponse.make(
            status_code=200,  # (optional) status code
            content=b'',
            headers=headers  # (optional) headers
        )

    @staticmethod
    def doh_query_checks():
        return [
            DohAddon._has_dns_message_content_type,
            DohAddon._request_has_dns_query_string,

            # For dns json we'd have to do some additional processing
            # in order to load it as a DNS message,
            # so we're just going to forget it for now.
            # DohProxyAddonBase._request_is_dns_json,

            DohAddon._requested_hostname_is_in_doh_blacklist,
            DohAddon._request_has_doh_looking_path
        ]

    @staticmethod
    def _has_dns_message_in_accept_header(flow: http.HTTPFlow) -> bool:
        """
        Check if HTTP request has a DNS-looking 'Accept' header

        :param flow: mitmproxy flow
        :return: True if 'Accept' header is DNS-looking, False otherwise
        """
        doh_content_types = {
            'application/dns-message'
        }
        return 'Accept' in flow.request.headers and flow.request.headers['Accept'] in doh_content_types

    @staticmethod
    def _has_dns_message_content_type(flow: http.HTTPFlow) -> bool:
        """
        Check if HTTP request has a DNS-looking 'Content-Type' header

        :param flow: mitmproxy flow
        :return: True if 'Content-Type' header is DNS-looking, False otherwise
        """
        doh_content_types = {
            'application/dns-message'
        }
        return 'Content-Type' in flow.request.headers and flow.request.headers['Content-Type'] in doh_content_types

    @staticmethod
    def _request_has_dns_query_string(flow):
        """
        Check if the query string of a request contains the parameter 'dns'

        :param flow: mitmproxy flow
        :return: True is 'dns' is a parameter in the query string, False otherwise
        """
        return 'dns' in flow.request.query

    @staticmethod
    def _request_is_dns_json(flow: http.HTTPFlow) -> bool:
        """
        Check if the request looks like DoH with JSON.

        The only known implementations of DoH with JSON are Cloudflare and Google.

        For more info, see:
        - https://developers.cloudflare.com/1.1.1.1/dns-over-https/json-format/
        - https://developers.google.com/speed/public-dns/docs/doh/json

        :param flow: mitmproxy flow
        :return: True is request looks like DNS JSON, False otherwise
        """
        # Header 'Accept: application/dns-json' is required in Cloudflare's DoH JSON API
        # or they return a 400 HTTP response code
        if 'Accept' in flow.request.headers:
            if flow.request.headers['Accept'] == 'application/dns-json':
                return True
        # Google's DoH JSON API is https://dns.google/resolve
        path = flow.request.path.split('?')[0]
        if flow.request.host == 'dns.google' and path == '/resolve':
            return True
        return False

    @staticmethod
    def _request_has_doh_looking_path(flow: http.HTTPFlow) -> bool:
        """
        Check if the path looks like it's DoH.
        Most common one is '/dns-query', likely because that's what's in the RFC

        :param flow: mitmproxy flow
        :return: True if path looks like it's DoH, otherwise False
        """
        doh_paths = {
            '/dns-query',  # used in example in RFC 8484 (see https://tools.ietf.org/html/rfc8484#section-4.1.1)
        }
        path = flow.request.path.split('?')[0]
        return path in doh_paths

    @staticmethod
    def _requested_hostname_is_in_doh_blacklist(flow: http.HTTPFlow) -> bool:
        """
        Check if server hostname is in our DoH provider blacklist.

        The current blacklist is taken from https://github.com/curl/curl/wiki/DNS-over-HTTPS.

        :param flow: mitmproxy flow
        :return: True if server's hostname is in DoH blacklist, otherwise False
        """
        hostname = flow.request.host
        ip = flow.server_conn.address
        return hostname in doh_hostnames or hostname in doh_ips or ip in doh_ips

addons = [
    DohAddon()
]
