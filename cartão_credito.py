import re
from burp import IBurpExtender, IHttpListener

# Função para validar números de cartão de crédito usando o Algoritmo de Luhn
def validate_credit_card(card_number):
    card_number = card_number.replace(" ", "")
    total = 0
    reverse_digits = card_number[::-1]
    
    for i, digit in enumerate(reverse_digits):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    
    return total % 10 == 0

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # Configurações iniciais
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Credit Card Scanner (Community)")
        callbacks.registerHttpListener(self)
        print("Credit Card Scanner para Burp Community, Instalado com sucesso!")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Processa apenas as respostas HTTP
        if not messageIsRequest:
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            
            # Extrai o corpo da resposta
            body_offset = response_info.getBodyOffset()
            body_bytes = messageInfo.getResponse()[body_offset:]
            body = self._helpers.bytesToString(body_bytes)
            
            # Padrão para capturar números de cartão de crédito (13 a 19 dígitos)
            card_pattern = re.compile(r'\b(?:\d[ -]*?){13,19}\b')
            possible_cards = card_pattern.findall(body)
            possible_cards = list(set(possible_cards))  # Remove duplicatas
            valid_cards = [card for card in possible_cards if validate_credit_card(card)]

            # Impressão de cartões de crédito válidos
            if valid_cards:
                print("Cartão de crédito válido encontrado: %s" % valid_cards[0])
                url = self._helpers.analyzeRequest(messageInfo).getUrl()
                print("Na URL: %s" % url)
