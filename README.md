# Collection of various OpenSMTPD filters

This collection of OpenSMTPD filters is described in my blog posts [Adding DKIM support to OpenSMTPD with custom filters](https://palant.info/2020/11/09/adding-dkim-support-to-opensmtpd-with-custom-filters/) and [Converting incoming emails on the fly with OpenSMTPD filters](https://palant.info/2023/03/08/converting-incoming-emails-on-the-fly-with-opensmtpd-filters/). No support is provided, use at your own risk.

## Installing

These scripts are most easily installed via [pipx](https://pipx.pypa.io/):

```sh
pipx install git+https://github.com/palant/opensmtpd-filters.git
```

Once installed, you can run the `dmarc2html-cli` command for example.

## dkimverify

This filter will perform DKIM and SPF verification on incoming mail. It can be used in `smtpd.conf` like this:

```
filter dkimverify proc-exec "/home/user/.local/share/pipx/venvs/opensmptd_filters/bin/dkimverify.py example.com"
listen on eth0 tls filter dkimverify
```

It takes a single command line parameter: the host name to appear in the `Authentication-Results` email header. It will add a header like `Authentication-Results: example.com; dkim=pass; spf=fail (sender is example.com/1.2.3.4) smtp.mailfrom=me@example.org` to emails, this header can then be considered in further processing.

## dkimsign

This filter will add a DKIM signature to outgoing emails. It can be used in `smtpd.conf` like this:

```
filter dkimsign proc-exec "/usr/local/bin/dkimsign.py example.com:mydkim:/etc/mail/dkim/mydkim.key"
listen on eth0 port 587 tls-require auth filter dkimsign
```

It takes one or multiple parameters of the form `domain:selector:keyfile` on the command line. Instead of configuring all domains on the command line, you can also pass this script `-c /etc/mail/dkim/dkim.conf` parameter, with the file `/etc/mail/dkim/dkim.conf` containing domain configurations in the same format, one per line.

## dmarc2html

This filter helps to simplify handling of DMARC aggregate reports for low-volume email servers. It can be used in `smtpd.conf` like this:

```
filter dmarc2html proc-exec "/home/user/.local/share/pipx/venvs/opensmptd_filters/bin/dmarc2html.py dmarc"
```
For any email to the `dmarc@…` account (or any other account specified as command line parameter), it will process the attachment and replace the email’s main part by the resulting HTML code.

There is also a script that will convert a DMARC aggregate report on the command line:

```
dmarc2html-cli dmarc.tar.gz
```

## spamhaus

This filter checks incoming connections against the Spamhaus blacklist.
You'll need a Spamhaus Data Query Service key, which you'll enter in `spamhauslib.py` as the `spamhaus_dqs_key`.
You probably qualify for a free key from [here](https://www.spamhaus.com/free-trial/sign-up-for-a-free-data-query-service-account/).

```
filter spamhaus proc-exec "/usr/local/bin/spamhaus.py mymailserver.example.com"
```
