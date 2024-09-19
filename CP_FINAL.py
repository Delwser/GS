# -*- coding: utf-8 -*-
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

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo, specific_number=None):
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
            found_items = []

            if credit_cards:
                found_items.extend([('Cartao de Credito', card) for card in credit_cards])
            if cpfs:
                found_items.extend([('CPF', cpf) for cpf in cpfs])
            if birth_dates:
                found_items.extend([('Data de Nascimento', date) for date in birth_dates])
            if phone_numbers:
                found_items.extend([('Telefone', phone) for phone in phone_numbers])

            if found_items:
                print("Dados pessoais encontrados na URL: %s" % url)
                # Converte os dados encontrados para strings
                found_items_str = ["{}: {}".format(data_type, item.encode('utf-8').decode('utf-8')) for data_type, item in found_items]
                print("Dados encontrados: %s" % found_items_str)
                
                # Verifica se o número específico foi encontrado
                if specific_number and any(item[1] == specific_number for item in found_items):
                    print("Número específico encontrado: %s" % specific_number)

# Ao instanciar a classe, a extensão será registrada e estará pronta para uso.
