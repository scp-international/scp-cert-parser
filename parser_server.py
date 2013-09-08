from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from urlparse import urlparse
import cgi

try:
    from scp_signer import create_cert, remove_csr
except Exception, e:
    print "Cannot import sign_cert (%s)..." % str(e)
    def create_cert(csr):
        name = os.path.join(CSR_DIR, os.path.basename(csr))
        print "Creating and signing cert from CSR (%s)..." % name
        pass
    
    def remove_csr(csr):
        name = os.path.join(CSR_DIR, os.path.basename(csr))
        print "Removing CSR (%s)..." % name
        pass
    
import os
from OpenSSL import crypto

CSR_DIR = "/tmp/csrs"

def show_pic(ext_data):
    pic_url = urlparse(ext_data if ext_data is not None else "")
    if pic_url.scheme not in ['http', 'https', 'file', 'ftp']:
        return "<div><b> Invalid pic url. </b></div>"
    else:
        return """
        <div><b> View pic: </b> <img src="%s://%s%s" width="300" height="300"/></div>
        """ % (pic_url.scheme, pic_url.netloc, pic_url.path)

def show_subject(subject):
    country = getattr(subject, "countryName", "")
    province = getattr(subject, "stateOrProvinceName", "")
    email = getattr(subject, "emailAddress", "")
    
    return """
    <div><b> Country:</b> %s </div>
    <div><b> Province:</b> %s </div>
    <div><b> Email:</b> %s </div>
    """ % (cgi.escape(str(country)), cgi.escape(str(province)), cgi.escape(str(email)))

def show_form(name):
    return """
    <form name="sign" method="POST" action="/">
       <input type="hidden" name="the_csr" value="%s" />
       <input type="submit" name="the_action" value="Sign CSR" />
       <input type="submit" name="the_action" value="Reject CSR" />
    </form>
    """ % str(name)

def show_page(data):
    return """
    <html>
    <head></head>
    <body> %s </body>
    </html>
    """ % data

def show_refresh():
    return """
    <meta http-equiv="refresh" content="5">
    """
    pass

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        response = ""
        
        try:
            csrs = os.listdir(CSR_DIR)
        except Exception, e:
            print "Could not list CSRs (%s)..." % str(e)
            csrs = []
            
        if len(csrs) == 0:
            print "No CSRs, waiting..."
            response += show_refresh()
            self.send_200()
            self.wfile.write(show_page(response))
            return
        
        try:
            name = os.path.join(CSR_DIR, csrs[0])
            print "Loading CSR (%s)..." % name
            cert = crypto.load_certificate_request(crypto.FILETYPE_PEM, file(name).read())
        except Exception, e:
            print "Could not load CSR (%s)..." % str(e)
            self.send_404()
            return
        
        try:
            subject = cert.get_subject()
            common_name = getattr(subject, "commonName", "")
            response += show_subject(subject)
            response += show_pic(common_name)
        except Exception, e:
            print "Could not parse x509 request (%s)..." % str(e)
            self.send_404()
            return
        
        response += show_form("../../../%s" % csrs[0])
        
        self.send_200()
        self.wfile.write(show_page(response))
        return
    
    def do_POST(self):
        content_type, post_dict = cgi.parse_header(self.headers.getheader('content-type'))
        
        print "Content-Type: %s" % content_type
        if content_type == 'multipart/form-data':
            post_vars = cgi.parse_multipart(self.rfile, post_dict)
        elif content_type == 'application/x-www-form-urlencoded':
            length = int(self.headers.getheader('content-length'))
            post_vars = cgi.parse_qs(self.rfile.read(length), keep_blank_values=1)
        else:
            self.send_404()
            return
        
        if "the_action" in post_vars and "the_csr" in post_vars:
            if post_vars["the_action"][0] == "Sign CSR":
                create_cert(post_vars["the_csr"][0])
            remove_csr(post_vars["the_csr"][0])

        self.do_GET()
        return

    def send_200(self):
        self.send_response(200)
        #self.send_header("Content-type", "application/json")
        self.end_headers()
        pass
    
    def send_404(self):
        self.send_response(404)
        self.end_headers()
        pass
    
        
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

if __name__ == '__main__':
    port = 45322
    server = ThreadedHTTPServer(('0.0.0.0', port), Handler)
    print 'Starting beta server (port %d), use <Ctrl-C> to stop' % port
    server.serve_forever()