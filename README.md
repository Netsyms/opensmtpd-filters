This is a set of scripts to simplify handling DMARC aggregate reports for low-volume email servers. No support provided, use at your own risk.

Requirements: [Jinja2](https://jinja.palletsprojects.com/intro/#installation)

`dmarc2html.py` is a command line conversion script. It takes the path to the aggregate report file as parameter and output HTML code.

`filter.py` is an OpenSMTPd filter process. For any email to the given account address, it will process the attachment and replace the email’s main part by the resulting HTML code.