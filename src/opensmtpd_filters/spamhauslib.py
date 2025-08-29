"""
This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    2014 Evox Computing Ltd - https://github.com/evoxco/python-spamhaus
    2025 Netsyms Technologies LLC
"""

import dns.resolver

spamhaus_dqs_key = ""

zen_return_codes = {'127.0.1.2': 'Spam domain',
                    '127.0.1.4': 'Phishing domain',
                    '127.0.1.5': 'Malware domain',
                    '127.0.1.6': 'Botnet C&C domain',
                    '127.0.1.102': 'Abused legit spam',
                    '127.0.1.103': 'Abused spammed redirector domain',
                    '127.0.1.104': 'Abused legit phish',
                    '127.0.1.105': 'Abused legit malware',
                    '127.0.1.106': 'Abused legit botnet C&C',
                    '127.0.1.255': 'IP queries prohibited!',
                    '127.0.0.2': 'Static UBE sources, verified spam services',
                    '127.0.0.3': 'Static UBE sources, verified spam services',
                    '127.0.0.4': 'Illegal 3rd party exploits, including'
                                  ' proxies, worms and trojan exploits',
                    '127.0.0.5': 'Illegal 3rd party exploits, including'
                                  ' proxies, worms and trojan exploits',
                    '127.0.0.6': 'Illegal 3rd party exploits, including'
                                  ' proxies, worms and trojan exploits',
                    '127.0.0.7': 'Illegal 3rd party exploits, including'
                                  ' proxies, worms and trojan exploits',
                    '127.0.0.10': 'IP ranges which should not be delivering'
                                   ' unauthenticated SMTP email',
                    '127.0.0.11': 'IP ranges which should not be delivering'
                                   ' unauthenticated SMTP email'

                    }

zen_return_codes_cif = {'127.0.1.2': 'Spam',
                    '127.0.1.4': 'Phishing',
                    '127.0.1.5': 'Malware',
                    '127.0.1.6': 'Botnet',
                    '127.0.1.102': 'Spam',
                    '127.0.1.103': 'Spam',
                    '127.0.1.104': 'Phishing',
                    '127.0.1.105': 'Malware',
                    '127.0.1.106': 'Botnet',
                    '127.0.1.255': 'Unknown!',
                    '127.0.0.2': 'Spam',
                    '127.0.0.3': 'Spam',
                    '127.0.0.4': 'Exploit',
                    '127.0.0.5': 'Exploit',
                    '127.0.0.6': 'Exploit',
                    '127.0.0.7': 'Exploit',
                    '127.0.0.10': 'Dynamic IP',
                    '127.0.0.11': 'Dynamic IP'

                    }


class SpamhausChecker:

    sp_response = {'status': '0',
                   'response_code': '',
                   'url': ''}

    @staticmethod
    def _reset_response(self):
        self.sp_response = {'status': '0',
                            'response_code': '',
                            'url': ''}

    def check_ip(self, ip_address):
        self._reset_response(self)
        sp_resolver = dns.resolver.Resolver()
        #sp_resolver.nameservers = ['8.8.8.8']

        try:


            _r_name = dns.reversename.from_address(ip_address)
            spamhaus_ip = spamhaus_dqs_key + ".zen.dq.spamhaus.net."
            lookup_name = str(_r_name).replace("in-addr.arpa.", spamhaus_ip)
            lookup_name = str(lookup_name).replace("ip6.arpa.", spamhaus_ip)
            
            # print(lookup_name)
            answers = sp_resolver.resolve(lookup_name, "A")

            for rdata in answers:
                # print(rdata.address)
                _url = 'https://check.spamhaus.org/results?query='+ip_address
                self.sp_response = {'status': '1',
                                    'response_code':
                                    zen_return_codes[rdata.address],
                                    'assessment':
                                    zen_return_codes_cif[rdata.address],
                                    'url': _url}
                return self.sp_response
        except:
            pass

        return self.sp_response
    
    def check_domain(self, domain):
        self._reset_response(self)
        sp_resolver = dns.resolver.Resolver()
        #sp_resolver.nameservers = ['8.8.8.8']

        for lookup in ["dbl", "zrd"]:
            try:
                lookuphost = domain + "." + spamhaus_dqs_key + "." + lookup + ".dq.spamhaus.net."
                #print(lookuphost)
                answers = sp_resolver.resolve(lookuphost, "A")
                
                for rdata in answers:
                    #print(rdata.address)
                    _url = 'https://check.spamhaus.org/results?query='+domain
                    octets = rdata.address.split(".")
                    if int(octets[2]) == 1 and int(octets[3]) in range(2, 99):
                        self.sp_response = {'status': '1',
                                        'response_code': "FROM domain blacklisted",
                                        'assessment': 'Banned',
                                        'url': _url}
                        return self.sp_response
                    if int(octets[2]) == 2 and int(octets[3]) < 24:
                        self.sp_response = {'status': '1',
                                        'response_code': "FROM domain too new: wait 24 hours for a sender reputation",
                                        'assessment': 'No reputation',
                                        'url': _url}
                        return self.sp_response
            except:
                pass

        return self.sp_response

if __name__ == "__main__":
    sh = SpamhausChecker()
    response = sh.check_ip("127.0.0.2")
    print(response)
    response = sh.check_domain("zrd-dqs.blt.spamhaus.net")
    print(response)
