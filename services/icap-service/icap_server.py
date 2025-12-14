import icapeg
from icapeg import ICAPServer, BaseICAPRequestHandler
import requests
import io

class AVICAPHandler(BaseICAPRequestHandler):
    def reqmod_OPTIONS(self, request):
        request.set_icap_response(200)
        request.set_icap_header('Methods', 'REQMOD')
        request.set_icap_header('Service', 'AV Scanner ICAP Service 1.0')
        request.send_headers()

    def reqmod_REQMOD(self, request):
        # Extract file from request if present
        if request.has_body:
            body = request.read_body()
            # Assume file upload, send to core-api
            files = {'file': ('uploaded_file', io.BytesIO(body), 'application/octet-stream')}
            response = requests.post('http://core-api:5000/scan', files=files)
            result = response.json()
            # If malicious, block
            if any('malicious' in str(v).lower() for v in result.values()):
                request.set_icap_response(403)
                request.set_icap_header('X-Reason', 'Malicious file detected')
                request.send_headers()
                return
        # Allow
        request.set_icap_response(200)
        request.send_headers(send_body=True)

if __name__ == '__main__':
    server = ICAPServer(('0.0.0.0', 1344), AVICAPHandler)
    server.serve_forever()
