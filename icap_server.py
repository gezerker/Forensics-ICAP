import pyicap
import socketserver
import logging
import os
import ssl
from pyicap import ICAPServer, BaseICAPRequestHandler

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(message)s')


class ThreadingICAPServer(socketserver.ThreadingMixIn, pyicap.ICAPServer):
    pass


class ICAPHandler(pyicap.BaseICAPRequestHandler):

    def _OPTIONS(self):
        """Handle OPTIONS requests."""
        logging.debug("OPTIONS request received.")
        self.set_icap_response(200)
        self.set_icap_header(b'Methods', b'REQMOD, RESPMOD')
        self.set_icap_header(b'Service', b'Python ICAP Server')
        self.set_icap_header(b'Preview', b'0')
        self.send_headers(False)
        logging.debug("OPTIONS request handled successfully.")
        
    def _REQMOD(self):
        """Handle REQMOD requests and save the full incoming HTTP request body to a file, logging it for comparison."""
        logging.debug("Handling REQMOD request.")
        
        # Set the ICAP response code to 200 OK
        self.set_icap_response(200)
        
        # Copy the encapsulated HTTP request status line and headers
        self.set_enc_request(b' '.join(self.enc_req))
        logging.debug(f"REQMOD request line: {self.enc_req}")
        
        logging.debug(f"REQMOD request headers: {self.enc_req_headers}")
        for h in self.enc_req_headers:
            for v in self.enc_req_headers[h]:
                self.set_enc_header(h, v)
        
        self.send_headers(has_body=True)

        # Initialize content holder and log the incoming body
        full_request_body = b''
        
        # Check if the body is chunked or has Content-Length
        if b'transfer-encoding' in self.enc_req_headers and \
           b'chunked' in [v.lower() for v in self.enc_req_headers[b'transfer-encoding']]:
            logging.debug("Body is chunked.")
            self.handle_chunked_body(full_request_body)
        elif b'content-length' in self.enc_req_headers:
            logging.debug("Body is not chunked, reading based on Content-Length.")
            self.handle_content_length_body(full_request_body)
        else:
            logging.error("Unknown body transfer encoding.")
            self.send_error(400, b'Bad Request')
            return

        # Log full request body for debugging
        logging.debug(f"Full incoming request body: {full_request_body.decode('utf-8', errors='ignore')}")
        self.log_request(200)
        logging.debug("REQMOD request handled successfully.")

    def handle_chunked_body(self, full_request_body):
        """Handle reading and writing a chunked request body."""
        try:
            with open('saved_request_body.txt', 'wb') as f:
                while True:
                    chunk = self.read_chunk()
                    if chunk == b'':
                        break
                    f.write(chunk)
                    full_request_body += chunk
                    self.write_chunk(chunk)
                self.write_chunk(b'')
                logging.debug("Request body saved to 'saved_request_body.txt'.")
        except Exception as e:
            logging.exception("Failed to save request body to file.")
            self.send_error(500, b'Internal Server Error')

    def handle_content_length_body(self, full_request_body):
        """Handle reading and writing a non-chunked request body using Content-Length."""
        try:
            content_length = int(self.enc_req_headers[b'content-length'][0])
            logging.debug(f"Content-Length: {content_length}")
            with open('saved_request_body.txt', 'wb') as f:
                body = self.rfile.read(content_length)
                f.write(body)
                full_request_body += body
                # Since the body is not chunked, write it directly
                self.wfile.write(body)
                logging.debug("Request body saved to 'saved_request_body.txt'.")
        except Exception as e:
            logging.exception("Failed to save request body to file.")
            self.send_error(500, b'Internal Server Error')

    def _RESPMOD(self):
        """Handle RESPMOD requests and save the HTTP response body to a file."""
        logging.debug("RESPMOD request received.")

        # Set the ICAP response code to 200 OK
        self.set_icap_response(200)

        # Set the encapsulated HTTP response status line
        if self.enc_res_status is not None:
            self.set_enc_status(b' '.join(self.enc_res_status))
        else:
            # If no status line is provided, set a default one
            self.set_enc_status(b'HTTP/1.1 200 OK')

        # Copy the encapsulated response headers
        for h in self.enc_res_headers:
            for v in self.enc_res_headers[h]:
                self.set_enc_header(h, v)

        # Prepare to send the ICAP headers
        if self.has_body:
            self.send_headers(has_body=True)
        else:
            self.send_headers(has_body=False)
            self.log_request(200)
            logging.debug("No body to process in RESPMOD request.")
            return

        # Read the HTTP response body and save it to a file
        try:
            logging.debug("Opening file to save response body.")
            with open('saved_response_body.txt', 'wb') as f:
                while True:
                    chunk = self.read_chunk()
                    if chunk == b'':
                        break
                    f.write(chunk)
                    # Send the chunk to the client as well
                    self.write_chunk(chunk)
            # Send the terminating chunk
            self.write_chunk(b'')
            logging.debug("Response body saved to 'saved_response_body.txt'.")
        except Exception as e:
            logging.exception("Failed to save response body to file.")
            # Optionally, you can send an error response back to the client
            self.send_error(500, b'Internal Server Error')
            return

        self.log_request(200)
        logging.debug("RESPMOD request handled successfully.")


def start_server():
    server_address = ('', 1344)
    
    # Define the server first before applying SSL wrapping
    httpd = ThreadingICAPServer(server_address, ICAPHandler)

    # Check if you want to enable SSL/TLS
    enable_ssl = True  # Change this to True if you want to enable SSL
    
    if enable_ssl:
        httpd.socket = ssl.wrap_socket(
            httpd.socket,
            certfile='cert.pem',  # Provide the path to your SSL certificate
            keyfile='key.pem',    # Provide the path to your SSL key
            server_side=True
        )
        logging.info(f'Starting ICAP server on port {server_address[1]} with SSL/TLS support...')
    else:
        logging.info(f'Starting ICAP server on port {server_address[1]}...')
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        logging.info('ICAP server stopped.')

if __name__ == '__main__':
    start_server()
