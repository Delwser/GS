import re
from burp import IBurpExtender, IHttpListener

# Funções para validação e busca de dados
def validate_credit_card(card_number):
    card_number = card_number.replace(" ", "").replace("-", "")
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

def find_credit_cards(body):
    card_pattern = re.compile(r'\b(?:\d[ -]*?){13,19}\b')
    return list(set(card_pattern.findall(body)))

def find_cpf(body):
    cpf_pattern = re.compile(r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b')
    return list(set(cpf_pattern.findall(body)))

def find_birth_dates(body):
    date_pattern = re.compile(r'\b\d{2}/\d{2}/\d{4}\b')
    return list(set(date_pattern.findall(body)))

def find_phone_numbers(body):
    phone_pattern = re.compile(r'\(\d{2}\) \d{4,5}-\d{4}')
    return list(set(phone_pattern.findall(body)))

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # Configurações iniciais
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Data Personal Scanner (Community)")
        callbacks.registerHttpListener(self)
        print("Scanner de Dados Pessoais para Burp Community, Instalado com sucesso!")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Processa apenas as respostas HTTP
        if not messageIsRequest:
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            
            # Extrai o corpo da resposta
            body_offset = response_info.getBodyOffset()
            body_bytes = messageInfo.getResponse()[body_offset:]
            body = self._helpers.bytesToString(body_bytes)

            # Busca por dados pessoais
            credit_cards = find_credit_cards(body)
            cpfs = find_cpf(body)
            birth_dates = find_birth_dates(body)
            phone_numbers = find_phone_numbers(body)

            # Impressão dos dados encontrados
            url = self._helpers.analyzeRequest(messageInfo).getUrl()
            if credit_cards or cpfs or birth_dates or phone_numbers:
                print("Dados pessoais encontrados na URL: %s" % url)
                if credit_cards:
                    print("Números de cartão de crédito encontrados: %s" % credit_cards)
                if cpfs:
                    print("CPFs encontrados: %s" % cpfs)
                if birth_dates:
                    print("Datas de nascimento encontradas: %s" % birth_dates)
                if phone_numbers:
                    print("Números de celular encontrados: %s" % phone_numbers)

# Ao instanciar a classe, a extensão será registrada e estará pronta para uso.
