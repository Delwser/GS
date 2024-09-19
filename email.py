import re
from burp import IBurpExtender, IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # Configurações iniciais
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Email Scanner (Community)")
        callbacks.registerHttpListener(self)
        print("Email Scanner para Burp Community, Instalado com sucesso!")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Processa apenas as respostas HTTP
        if not messageIsRequest:
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            
            # Extrai o corpo da resposta
            body_offset = response_info.getBodyOffset()
            body_bytes = messageInfo.getResponse()[body_offset:]
            body = self._helpers.bytesToString(body_bytes)
            
            # Padrão para capturar e-mails
            email_pattern = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
            emails = email_pattern.findall(body)
            emails = list(set(emails))  # Remove duplicatas

            # Impressão de endereços de e-mail
            if emails:
                print("E-mails encontrados: %s" % ", ".join(emails))
                url = self._helpers.analyzeRequest(messageInfo).getUrl()
                print("Na URL: %s" % url)
